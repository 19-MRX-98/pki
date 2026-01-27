# pki

Einfache Web-App zur Verwaltung einer kleinen PKI mit OpenSSL.

## Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Die Web-App läuft dann unter `http://localhost:5000`.

Hinweis: Browser-Fehler `net::ERR_CERT_COMMON_NAME_INVALID` bedeutet meist, dass der Hostname/IP der URL nicht im Zertifikat als SAN enthalten ist. In der Web-App werden CN sowie die angegebenen Hostnames/IPs als SAN gesetzt.

## Anmeldung

- Standardlogin: `admin` / `admin`
- Benutzerverwaltung und Passwort-Änderung sind im Menüpunkt **Benutzer** verfügbar.
- Datenbank: `data/pki.db` (SQLite)

## Zertifikate zurückziehen/löschen

- Zurückziehen erzeugt eine CRL (Certificate Revocation List). Diese kann im UI heruntergeladen werden.
- Löschen entfernt nur die lokalen Dateien des ausgestellten Zertifikats.
- Bereits bestehende Zertifikate müssen ggf. neu erstellt werden, damit sie in der OpenSSL-Datenbank für das Zurückziehen geführt werden.

## Mehrere CAs

- CAs werden unter `data/ca/<slug>/` verwaltet, Zertifikate unter `data/issued/<ca-slug>/`.
- Beim ersten Start werden bestehende Daten automatisch nach `default` migriert.
- Im Zertifikate-Formular die gewünschte CA per Dropdown auswählen.

## CSR importieren

- Im Bereich **CSR importieren** eine CSR-Datei (PEM) auswählen und signieren.
- Optional kann der passende Private Key hochgeladen werden, um ihn zentral abzulegen.
- CSR und Private Key werden vor dem Signieren auf Übereinstimmung geprüft.

## Nginx Integration (Reverse Proxy)

- Auf der Zertifikats-Detailseite kann eine Nginx-Konfiguration erzeugt werden.
- Standardpfade:
  - vHosts: `/etc/nginx/sites-enabled`
  - Zertifikate: `/etc/nginx/certs`
- Konfiguration per ENV anpassbar:
  - `NGINX_SITES_DIR`
  - `NGINX_CERTS_DIR`
- Automatischer Reload:
  - Standard: `nginx -s reload`
  - Wenn nginx in einem eigenen Container läuft:
    - `NGINX_RELOAD_CONTAINER=pki-reverseproxy`
    - Docker Socket mounten: `/var/run/docker.sock`
  - Falls keine Docker-CLI im Container vorhanden ist, wird die Docker API über den Socket genutzt.
  - Alternativ eigener Befehl: `NGINX_RELOAD_CMD="docker exec pki-reverseproxy nginx -s reload"`
- Nach dem Schreiben wird `nginx -s reload` ausgeführt (App benötigt die Rechte).
- Upstream-Vorschläge (optional):
  - ENV: `NGINX_UPSTREAM_SUGGESTIONS` (CSV)
  - Datei: `data/upstreams.txt` (Zeilen: `Label|URL` oder nur `URL`)

### Hinweis zu Ports (Variante B)

- Wenn auf dem Host Port 80 belegt ist, kann der Nginx-Container nur HTTPS nach außen exponieren:
  - `8443:443`
- Zugriff erfolgt dann über: `https://<host>:8443`
- Für den ersten Zugriff auf die PKI-App ist im Compose zusätzlich `5000:5000` gemappt,
  damit du Zertifikate erzeugen und die Nginx-Deploy-Funktion nutzen kannst.
  Danach kannst du den Port optional wieder entfernen.

## Docker

```bash
docker build -t pki-app .
docker run --rm -p 5000:5000 -e FLASK_SECRET_KEY="bitte-aendern" -v "$(pwd)/data:/app/data" pki-app
```
