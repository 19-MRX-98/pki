from __future__ import annotations

import datetime
import os
import shutil
import subprocess

from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from pathlib import Path
from werkzeug.utils import secure_filename

from pki_auth import (
    create_user,
    delete_user,
    ensure_db,
    list_users,
    update_password,
    verify_user,
)
from pki_ca import ca_crl_path, ca_exists, create_ca, generate_crl
from pki_certificates import (
    issue_certificate,
    issue_from_csr,
    revoke_certificate,
    verify_key_matches_csr,
)
from pki_nginx import (
    delete_vhost,
    get_vhost,
    list_vhosts,
    load_defaults,
    list_local_containers,
    list_swarm_services,
    parse_domains,
    reload_nginx,
    save_defaults,
    validate_domains,
    write_nginx_files,
    write_vhost_only,
    write_cert_files,
)
from pki_paths import CA_ROOT
from pki_storage import (
    get_ca_dir,
    get_ca_name,
    get_cert_dir,
    get_revoked_marker,
    list_cas,
    list_crls,
    list_certificates_with_keys,
    get_crl_entries,
    list_upstream_suggestions,
    list_issued,
    prepare_storage,
    resolve_selected_ca,
)
from pki_utils import run_openssl_capture

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
NGINX_FEATURES = os.environ.get("NGINX_FEATURES", "1") != "0"


@app.before_request
def require_authentication():
    if request.endpoint in {"login", "static"}:
        ensure_db()
        return None
    ensure_db()
    if "user_id" not in session:
        return redirect(url_for("login", next=request.full_path))
    return None


@app.context_processor
def inject_user():
    return {"current_user": session.get("username"), "nginx_enabled": NGINX_FEATURES}


def build_nav_links(selected_ca: str) -> dict[str, str]:
    if selected_ca:
        return {
            "home": url_for("home", ca=selected_ca),
            "cas_page": url_for("cas_page", ca=selected_ca),
            "certs_page": url_for("certs_page", ca=selected_ca),
            "crl_page": url_for("crl_page", ca=selected_ca),
            "users_page": url_for("users_page", ca=selected_ca),
            "nginx_page": url_for("nginx_page", ca=selected_ca),
        }
    return {
        "home": url_for("home"),
        "cas_page": url_for("cas_page"),
        "certs_page": url_for("certs_page"),
        "crl_page": url_for("crl_page"),
        "users_page": url_for("users_page"),
        "nginx_page": url_for("nginx_page"),
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    ensure_db()
    error = None
    next_param = request.args.get("next") or ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            next_url = request.form.get("next") or url_for("home")
            return redirect(next_url)
        error = "Ungültige Zugangsdaten."
    return render_template("login.html", error=error, next_param=next_param)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
def home() -> str:
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, request.args.get("ca"))
    nav_links = build_nav_links(selected_ca)
    issued_count = len(list_issued(selected_ca)) if selected_ca else 0
    return render_template(
        "home.html",
        active_page="home",
        nav_links=nav_links,
        cas=cas,
        ca_count=len(cas),
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        issued_count=issued_count,
    )


@app.route("/cas", methods=["GET"])
def cas_page() -> str:
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, request.args.get("ca"))
    nav_links = build_nav_links(selected_ca)
    return render_template(
        "cas.html",
        active_page="cas_page",
        nav_links=nav_links,
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
    )


@app.route("/certs", methods=["GET"])
def certs_page() -> str:
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, request.args.get("ca"))
    nav_links = build_nav_links(selected_ca)
    return render_template(
        "certs.html",
        active_page="certs_page",
        nav_links=nav_links,
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        issued=list_issued(selected_ca) if selected_ca else [],
    )


@app.route("/nginx", methods=["GET"])
def nginx_page() -> str:
    if not NGINX_FEATURES:
        return redirect(url_for("home"))
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, request.args.get("ca"))
    nav_links = build_nav_links(selected_ca)
    defaults = load_defaults()
    vhosts = list_vhosts()
    domains = []
    for item in vhosts:
        for domain in item.get("server_names", []):
            domains.append(domain)
    if not domains:
        for item in vhosts:
            name = str(item.get("name", ""))
            if name.endswith(".conf"):
                domains.append(name[:-5])
    domains = sorted(set(domains))
    containers = list_local_containers()
    swarm_services = list_swarm_services()
    return render_template(
        "nginx.html",
        active_page="nginx_page",
        nav_links=nav_links,
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        defaults=defaults,
        vhosts=vhosts,
        domains=domains,
        certificates=list_certificates_with_keys(),
        upstream_suggestions=list_upstream_suggestions(),
        containers=containers,
        swarm_services=swarm_services,
    )


@app.route("/nginx/defaults", methods=["POST"])
def nginx_defaults_route():
    if not NGINX_FEATURES:
        return redirect(url_for("home"))
    upstream_url = request.form.get("upstream_url", "").strip()
    redirect_http = bool(request.form.get("redirect_http"))
    save_defaults(upstream_url, redirect_http)
    flash("Defaults gespeichert.", "success")
    return redirect(url_for("nginx_page"))


@app.route("/nginx/create", methods=["POST"])
def nginx_create_route():
    if not NGINX_FEATURES:
        return redirect(url_for("home"))
    primary_domain = request.form.get("primary_domain", "").strip()
    extra_domains = request.form.get("extra_domains", "").strip()
    upstream_url = request.form.get("upstream_url", "").strip()
    redirect_http = bool(request.form.get("redirect_http"))
    cert_choice = request.form.get("cert_choice", "").strip()

    if not primary_domain:
        flash("Bitte eine Domain angeben.", "error")
        return redirect(url_for("nginx_page"))
    if not upstream_url or not upstream_url.startswith(("http://", "https://")) or " " in upstream_url:
        flash("Ungültige Upstream-URL.", "error")
        return redirect(url_for("nginx_page"))

    domains = parse_domains(primary_domain, extra_domains)
    valid_domains = validate_domains(domains)
    if primary_domain not in valid_domains:
        flash("Primäre Domain ist ungültig.", "error")
        return redirect(url_for("nginx_page"))
    if not valid_domains:
        flash("Keine gültigen Domains gefunden.", "error")
        return redirect(url_for("nginx_page"))

    cert_map = {item["label"]: item for item in list_certificates_with_keys()}
    cert_entry = cert_map.get(cert_choice)
    if not cert_entry:
        flash("Bitte ein Zertifikat auswählen.", "error")
        return redirect(url_for("nginx_page"))

    try:
        cert_pem = Path(cert_entry["cert_path"]).read_text(encoding="utf-8")
        key_pem = Path(cert_entry["key_path"]).read_text(encoding="utf-8")
        ca_slug = cert_entry["ca_slug"]
        ca_dir = get_ca_dir(ca_slug)
        ca_pem = None
        if ca_dir:
            ca_cert_path = ca_dir / "certs" / "ca.crt"
            if ca_cert_path.exists():
                ca_pem = ca_cert_path.read_text(encoding="utf-8")
        write_nginx_files(
            primary_domain,
            valid_domains,
            upstream_url,
            cert_pem,
            key_pem,
            ca_pem,
            redirect_http,
        )
        reload_nginx()
    except (OSError, RuntimeError) as exc:
        flash(f"Nginx-Konfiguration konnte nicht geschrieben oder geladen werden: {exc}", "error")
        return redirect(url_for("nginx_page"))

    flash("VHost erstellt und Nginx neu geladen.", "success")
    return redirect(url_for("nginx_page"))


@app.route("/nginx/edit/<name>", methods=["GET", "POST"])
def nginx_edit_route(name: str):
    if not NGINX_FEATURES:
        return redirect(url_for("home"))
    vhost_path, vhost = get_vhost(name)
    if not vhost:
        flash("VHost nicht gefunden.", "error")
        return redirect(url_for("nginx_page"))

    if request.method == "POST":
        server_names = request.form.get("server_names", "").strip()
        upstream_url = request.form.get("upstream_url", "").strip()
        redirect_http = bool(request.form.get("redirect_http"))
        cert_choice = request.form.get("cert_choice", "").strip()

        if not server_names:
            flash("Bitte Domains angeben.", "error")
            return redirect(url_for("nginx_edit_route", name=name))
        domains = [item.strip() for item in server_names.split(",") if item.strip()]
        valid_domains = validate_domains(domains)
        if not valid_domains:
            flash("Keine gültigen Domains gefunden.", "error")
            return redirect(url_for("nginx_edit_route", name=name))
        if not upstream_url or not upstream_url.startswith(("http://", "https://")) or " " in upstream_url:
            flash("Ungültige Upstream-URL.", "error")
            return redirect(url_for("nginx_edit_route", name=name))

        try:
            if cert_choice:
                cert_map = {item["label"]: item for item in list_certificates_with_keys()}
                cert_entry = cert_map.get(cert_choice)
                if not cert_entry:
                    flash("Zertifikat nicht gefunden.", "error")
                    return redirect(url_for("nginx_edit_route", name=name))
                cert_pem = Path(cert_entry["cert_path"]).read_text(encoding="utf-8")
                key_pem = Path(cert_entry["key_path"]).read_text(encoding="utf-8")
                ca_slug = cert_entry["ca_slug"]
                ca_dir = get_ca_dir(ca_slug)
                ca_pem = None
                if ca_dir:
                    ca_cert_path = ca_dir / "certs" / "ca.crt"
                    if ca_cert_path.exists():
                        ca_pem = ca_cert_path.read_text(encoding="utf-8")
                cert_path = Path(vhost.get("cert_path") or "")
                key_path = Path(vhost.get("key_path") or "")
                if cert_path and key_path:
                    write_cert_files(cert_path, key_path, cert_pem, key_pem, ca_pem)

            cert_path = Path(vhost.get("cert_path") or "")
            key_path = Path(vhost.get("key_path") or "")
            write_vhost_only(vhost_path, valid_domains, upstream_url, cert_path, key_path, redirect_http)
            reload_nginx()
        except (OSError, RuntimeError) as exc:
            flash(f"Nginx-Konfiguration konnte nicht geschrieben oder geladen werden: {exc}", "error")
            return redirect(url_for("nginx_edit_route", name=name))

        flash("VHost aktualisiert.", "success")
        return redirect(url_for("nginx_page"))

    defaults = load_defaults()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, request.args.get("ca"))
    return render_template(
        "nginx_edit.html",
        active_page="nginx_page",
        nav_links=build_nav_links(selected_ca),
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        vhost=vhost,
        name=name,
        defaults=defaults,
        certificates=list_certificates_with_keys(),
        upstream_suggestions=list_upstream_suggestions(),
    )


@app.route("/nginx/delete/<name>", methods=["POST"])
def nginx_delete_route(name: str):
    if not NGINX_FEATURES:
        return redirect(url_for("home"))
    try:
        delete_vhost(name)
        reload_nginx()
    except (OSError, RuntimeError) as exc:
        flash(f"VHost konnte nicht gelöscht werden: {exc}", "error")
        return redirect(url_for("nginx_page"))
    flash("VHost gelöscht.", "success")
    return redirect(url_for("nginx_page"))

@app.route("/crl", methods=["GET"])
def crl_page() -> str:
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, request.args.get("ca"))
    nav_links = build_nav_links(selected_ca)
    return render_template(
        "crl.html",
        active_page="crl_page",
        nav_links=nav_links,
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        crls=list_crls(),
    )


@app.route("/crl/<slug>", methods=["GET"])
def crl_detail_page(slug: str) -> str:
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, slug)
    nav_links = build_nav_links(selected_ca)
    ca_dir = get_ca_dir(slug)
    if not ca_dir:
        flash("CA nicht gefunden.", "error")
        return redirect(url_for("crl_page"))
    entries = get_crl_entries(ca_dir)
    return render_template(
        "crl_detail.html",
        active_page="crl_page",
        nav_links=nav_links,
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        slug=slug,
        entries=entries,
    )


@app.route("/users", methods=["GET"])
def users_page() -> str:
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, request.args.get("ca"))
    nav_links = build_nav_links(selected_ca)
    return render_template(
        "users.html",
        active_page="users_page",
        nav_links=nav_links,
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        users=list_users(),
        current_user=session.get("username"),
    )


@app.route("/users/create", methods=["POST"])
def create_user_route():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        flash("Bitte Benutzername und Passwort angeben.", "error")
        return redirect(url_for("users_page"))
    if not create_user(username, password):
        flash("Benutzer konnte nicht erstellt werden (Name existiert bereits).", "error")
        return redirect(url_for("users_page"))
    flash("Benutzer erstellt.", "success")
    return redirect(url_for("users_page"))


@app.route("/users/<int:user_id>/password", methods=["POST"])
def reset_password_route(user_id: int):
    new_password = request.form.get("new_password", "")
    if not new_password:
        flash("Neues Passwort fehlt.", "error")
        return redirect(url_for("users_page"))
    update_password(user_id, new_password)
    flash("Passwort aktualisiert.", "success")
    return redirect(url_for("users_page"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
def delete_user_route(user_id: int):
    if session.get("user_id") == user_id:
        flash("Du kannst deinen eigenen Benutzer nicht löschen.", "error")
        return redirect(url_for("users_page"))
    delete_user(user_id)
    flash("Benutzer gelöscht.", "success")
    return redirect(url_for("users_page"))


@app.route("/users/me/password", methods=["POST"])
def change_password_route():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))
    if not current_password or not new_password:
        flash("Bitte aktuelles und neues Passwort angeben.", "error")
        return redirect(url_for("users_page"))
    if not verify_user(username, current_password):
        flash("Aktuelles Passwort ist falsch.", "error")
        return redirect(url_for("users_page"))
    update_password(session["user_id"], new_password)
    flash("Passwort geändert.", "success")
    return redirect(url_for("users_page"))


@app.route("/issued/<ca_slug>/<slug>/view", methods=["GET"])
def view_issued(ca_slug: str, slug: str):
    prepare_storage()
    cas = list_cas()
    selected_ca = resolve_selected_ca(cas, ca_slug)
    nav_links = build_nav_links(selected_ca)
    cert_dir = get_cert_dir(ca_slug, slug)
    if not cert_dir:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=selected_ca))
    cert_path = next(cert_dir.glob("*.crt"), None)
    if not cert_path:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=selected_ca))

    key_path = next(cert_dir.glob("*.key"), None)

    try:
        raw_cert = cert_path.read_text(encoding="utf-8")
    except OSError:
        flash("Zertifikat konnte nicht gelesen werden.", "error")
        return redirect(url_for("certs_page", ca=selected_ca))

    try:
        details = run_openssl_capture(["x509", "-noout", "-text", "-in", str(cert_path)])
    except subprocess.CalledProcessError:
        details = "Details konnten nicht geladen werden."

    revoked_at = get_revoked_marker(cert_dir)

    return render_template(
        "cert_view.html",
        active_page="certs_page",
        nav_links=nav_links,
        cas=cas,
        selected_ca=selected_ca,
        selected_ca_name=get_ca_name(cas, selected_ca) if selected_ca else "",
        slug=slug,
        raw_cert=raw_cert,
        details=details,
        revoked_at=revoked_at,
        key_available=key_path is not None,
        upstream_suggestions=list_upstream_suggestions(),
    )


@app.route("/nginx/deploy/<ca_slug>/<slug>", methods=["POST"])
def deploy_to_nginx(ca_slug: str, slug: str):
    prepare_storage()
    ca_dir = get_ca_dir(ca_slug)
    if not ca_dir or not ca_exists(ca_dir):
        flash("Keine CA vorhanden.", "error")
        return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))

    cert_dir = get_cert_dir(ca_slug, slug)
    if not cert_dir:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    cert_path = next(cert_dir.glob("*.crt"), None)
    key_path = next(cert_dir.glob("*.key"), None)
    if not cert_path:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))
    if not key_path:
        flash("Private Key fehlt für die nginx-Integration.", "error")
        return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))

    primary_domain = request.form.get("primary_domain", "").strip()
    extra_domains = request.form.get("extra_domains", "").strip()
    upstream_url = request.form.get("upstream_url", "").strip()
    redirect_http = bool(request.form.get("redirect_http"))

    if not primary_domain:
        flash("Bitte eine Domain angeben.", "error")
        return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))
    if not upstream_url or not upstream_url.startswith(("http://", "https://")) or " " in upstream_url:
        flash("Ungültige Upstream-URL.", "error")
        return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))

    domains = parse_domains(primary_domain, extra_domains)
    valid_domains = validate_domains(domains)
    if primary_domain not in valid_domains:
        flash("Primäre Domain ist ungültig.", "error")
        return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))
    if not valid_domains:
        flash("Keine gültigen Domains gefunden.", "error")
        return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))

    try:
        cert_pem = cert_path.read_text(encoding="utf-8")
        key_pem = key_path.read_text(encoding="utf-8")
        ca_cert_path = ca_dir / "certs" / "ca.crt"
        ca_pem = ca_cert_path.read_text(encoding="utf-8") if ca_cert_path.exists() else None
        write_nginx_files(
            primary_domain,
            valid_domains,
            upstream_url,
            cert_pem,
            key_pem,
            ca_pem,
            redirect_http,
        )
        reload_nginx()
    except (OSError, RuntimeError) as exc:
        flash(f"Nginx-Konfiguration konnte nicht geschrieben oder geladen werden: {exc}", "error")
        return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))

    flash("Nginx-Konfiguration geschrieben und geladen.", "success")
    return redirect(url_for("view_issued", ca_slug=ca_slug, slug=slug))


@app.route("/ca", methods=["POST"])
def create_ca_route():
    prepare_storage()
    common_name = request.form.get("ca_common_name", "").strip()
    ca_slug = request.form.get("ca_slug", "").strip()
    days_valid = int(request.form.get("ca_days_valid", "3650"))
    if not common_name:
        flash("Bitte einen Common Name für die CA angeben.", "error")
        return redirect(url_for("cas_page"))
    safe_slug = secure_filename(ca_slug) or secure_filename(common_name) or "ca"
    final_slug = safe_slug
    counter = 1
    while (CA_ROOT / final_slug).exists():
        final_slug = f"{safe_slug}-{counter}"
        counter += 1
    ca_dir = CA_ROOT / final_slug
    try:
        create_ca(ca_dir, common_name, days_valid)
    except subprocess.CalledProcessError:
        flash("Fehler beim Erstellen der CA. Prüfe die OpenSSL-Installation.", "error")
        return redirect(url_for("cas_page", ca=final_slug))
    flash("CA erfolgreich erstellt.", "success")
    try:
        generate_crl(ca_dir)
    except subprocess.CalledProcessError:
        flash("CRL konnte nicht erzeugt werden.", "error")
    return redirect(url_for("cas_page", ca=final_slug))


@app.route("/cert", methods=["POST"])
def create_cert_route():
    prepare_storage()
    ca_slug = request.form.get("ca_slug", "").strip()
    if not ca_slug:
        flash("Bitte eine CA auswählen.", "error")
        return redirect(url_for("certs_page"))
    ca_dir = get_ca_dir(ca_slug)
    if not ca_dir or not ca_exists(ca_dir):
        flash("Bitte zuerst eine CA erstellen.", "error")
        return redirect(url_for("certs_page"))

    common_name = request.form.get("common_name", "").strip()
    organization = request.form.get("organization", "").strip()
    country = request.form.get("country", "").strip()
    hostnames = [value.strip() for value in request.form.get("hostnames", "").split(",") if value.strip()]
    ip_addresses = [value.strip() for value in request.form.get("ip_addresses", "").split(",") if value.strip()]
    days_valid = int(request.form.get("validity_days", "365"))
    if days_valid not in {90, 365, 730}:
        flash("Ungültige Gültigkeit gewählt.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    if not common_name:
        flash("Bitte einen Common Name für das Zertifikat angeben.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    try:
        issue_certificate(
            ca_dir, common_name, organization, country, hostnames, ip_addresses, days_valid
        )
    except subprocess.CalledProcessError:
        flash("Fehler beim Erstellen des Zertifikats. Prüfe die OpenSSL-Installation.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    flash("Zertifikat erfolgreich erstellt.", "success")
    return redirect(url_for("certs_page", ca=ca_slug))


@app.route("/cert/csr", methods=["POST"])
def import_csr_route():
    prepare_storage()
    ca_slug = request.form.get("ca_slug", "").strip()
    if not ca_slug:
        flash("Bitte eine CA auswählen.", "error")
        return redirect(url_for("certs_page"))
    ca_dir = get_ca_dir(ca_slug)
    if not ca_dir or not ca_exists(ca_dir):
        flash("Bitte zuerst eine CA erstellen.", "error")
        return redirect(url_for("certs_page"))

    file = request.files.get("csr_file")
    if not file or not file.filename:
        flash("Bitte CSR-Datei auswählen.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))
    key_file = request.files.get("key_file")

    days_valid = int(request.form.get("validity_days", "365"))
    if days_valid not in {90, 365, 730}:
        flash("Ungültige Gültigkeit gewählt.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    try:
        csr_bytes = file.read()
    except OSError:
        flash("CSR konnte nicht gelesen werden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))
    key_bytes = b""
    if key_file and key_file.filename:
        try:
            key_bytes = key_file.read()
        except OSError:
            flash("Private Key konnte nicht gelesen werden.", "error")
            return redirect(url_for("certs_page", ca=ca_slug))

    if b"BEGIN CERTIFICATE REQUEST" not in csr_bytes:
        flash("Ungültige CSR-Datei.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))
    if key_bytes:
        if b"BEGIN" not in key_bytes:
            flash("Ungültiger Private Key.", "error")
            return redirect(url_for("certs_page", ca=ca_slug))
        if not verify_key_matches_csr(csr_bytes, key_bytes):
            flash("CSR und Private Key passen nicht zusammen.", "error")
            return redirect(url_for("certs_page", ca=ca_slug))

    try:
        cert_slug, _cert_path, _csr_path, cert_dir = issue_from_csr(
            ca_dir, csr_bytes, days_valid
        )
    except subprocess.CalledProcessError:
        flash("Fehler beim Signieren des CSR.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))
    if key_bytes:
        key_path = cert_dir / f"{cert_slug}.key"
        try:
            key_path.write_bytes(key_bytes)
        except OSError:
            flash("Private Key konnte nicht gespeichert werden.", "error")
            return redirect(url_for("certs_page", ca=ca_slug))

    flash("CSR erfolgreich signiert.", "success")
    return redirect(url_for("certs_page", ca=ca_slug))


@app.route("/ca/<slug>/download", methods=["GET"])
def download_ca(slug: str):
    prepare_storage()
    ca_dir = get_ca_dir(slug)
    if not ca_dir or not ca_exists(ca_dir):
        flash("Keine CA vorhanden.", "error")
        return redirect(url_for("cas_page", ca=slug))
    return send_file(
        ca_dir / "certs" / "ca.crt", as_attachment=True, download_name=f"{slug}.ca.crt"
    )


@app.route("/ca/<slug>/crl", methods=["GET"])
def download_crl(slug: str):
    prepare_storage()
    ca_dir = get_ca_dir(slug)
    if not ca_dir:
        flash("Keine CA vorhanden.", "error")
        return redirect(url_for("cas_page", ca=slug))
    crl_path = ca_crl_path(ca_dir)
    if not crl_path.exists():
        flash("Keine CRL vorhanden.", "error")
        return redirect(url_for("cas_page", ca=slug))
    return send_file(crl_path, as_attachment=True, download_name=f"{slug}.crl")


@app.route("/ca/<slug>/crl/generate", methods=["POST"])
def generate_crl_route(slug: str):
    prepare_storage()
    ca_dir = get_ca_dir(slug)
    if not ca_dir or not ca_exists(ca_dir):
        flash("Keine CA vorhanden.", "error")
        return redirect(url_for("cas_page", ca=slug))
    try:
        generate_crl(ca_dir)
    except subprocess.CalledProcessError:
        flash("CRL konnte nicht erzeugt werden.", "error")
        return redirect(url_for("cas_page", ca=slug))
    flash("CRL wurde erzeugt.", "success")
    return redirect(url_for("cas_page", ca=slug))


@app.route("/download/issued/<ca_slug>/<slug>/<filetype>", methods=["GET"])
def download_issued(ca_slug: str, slug: str, filetype: str):
    prepare_storage()
    safe_slug = secure_filename(slug) or "certificate"
    cert_dir = get_cert_dir(ca_slug, slug)
    if not cert_dir:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    if filetype == "cert":
        file_path = next(cert_dir.glob("*.crt"), None)
        download_name = f"{safe_slug}.crt"
    elif filetype == "key":
        file_path = next(cert_dir.glob("*.key"), None)
        download_name = f"{safe_slug}.key"
    else:
        flash("Ungültiger Dateityp.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    if not file_path:
        flash("Datei nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))
    return send_file(file_path, as_attachment=True, download_name=download_name)


@app.route("/issued/<ca_slug>/<slug>/revoke", methods=["POST"])
def revoke_issued(ca_slug: str, slug: str):
    prepare_storage()
    ca_dir = get_ca_dir(ca_slug)
    if not ca_dir or not ca_exists(ca_dir):
        flash("Keine CA vorhanden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    cert_dir = get_cert_dir(ca_slug, slug)
    if not cert_dir:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    cert_path = next(cert_dir.glob("*.crt"), None)
    if not cert_path:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    try:
        revoke_certificate(ca_dir, cert_path)
    except subprocess.CalledProcessError:
        flash("Fehler beim Zurückziehen des Zertifikats.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    revoked_marker = cert_dir / "revoked.txt"
    revoked_marker.write_text(datetime.datetime.now(tz=datetime.UTC).isoformat(), encoding="utf-8")
    flash("Zertifikat zurückgezogen. CRL wurde aktualisiert.", "success")
    return redirect(url_for("certs_page", ca=ca_slug))


@app.route("/issued/<ca_slug>/<slug>/delete", methods=["POST"])
def delete_issued(ca_slug: str, slug: str):
    prepare_storage()
    cert_dir = get_cert_dir(ca_slug, slug)
    if not cert_dir:
        flash("Zertifikat nicht gefunden.", "error")
        return redirect(url_for("certs_page", ca=ca_slug))

    shutil.rmtree(cert_dir)
    flash("Zertifikat gelöscht.", "success")
    return redirect(url_for("certs_page", ca=ca_slug))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
