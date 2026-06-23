import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from werkzeug.utils import secure_filename

from pki_ca import ensure_ca_config, ensure_ca_dirs
from pki_paths import CA_ROOT
from pki_utils import run_openssl_capture


class CaImportError(ValueError):
    pass


REQUIRED_FILES = {
    PurePosixPath("certs/ca.crt"),
    PurePosixPath("private/ca.key"),
    PurePosixPath("index.txt"),
    PurePosixPath("serial"),
    PurePosixPath("crlnumber"),
}
REQUIRED_DIRS = {
    PurePosixPath("newcerts"),
    PurePosixPath("crl"),
}
ROOT_ITEMS = {
    "certs",
    "private",
    "newcerts",
    "crl",
    "index.txt",
    "serial",
    "crlnumber",
    "openssl.cnf",
}


@dataclass(frozen=True)
class ZipMember:
    name: str
    path: PurePosixPath
    is_dir: bool


def _safe_zip_members(archive: zipfile.ZipFile) -> list[ZipMember]:
    members: list[ZipMember] = []
    for info in archive.infolist():
        name = info.filename
        is_dir = info.is_dir()
        if (
            not name
            or name.startswith("/")
            or "\\" in name
        ):
            raise CaImportError("Import abgebrochen: unsichere ZIP-Pfade gefunden.")

        raw_parts = name.split("/")
        if is_dir and raw_parts[-1] == "":
            raw_parts = raw_parts[:-1]
        path = PurePosixPath(name)
        if (
            not raw_parts
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in raw_parts)
        ):
            raise CaImportError("Import abgebrochen: unsichere ZIP-Pfade gefunden.")

        members.append(ZipMember(name=name, path=PurePosixPath(*raw_parts), is_dir=is_dir))
    return members


def _top_level_folder(paths: list[PurePosixPath]) -> str | None:
    top_level_folders = {
        path.parts[0]
        for path in paths
        if len(path.parts) > 1 and path.parts[0] not in ROOT_ITEMS
    }
    if len(top_level_folders) > 1:
        raise CaImportError("Import abgebrochen: mehrere Top-Level-Ordner gefunden.")
    if len(top_level_folders) == 1:
        return next(iter(top_level_folders))
    return None


def _strip_top_level(path: PurePosixPath, folder: str | None) -> PurePosixPath | None:
    if folder is None:
        return path
    if path.parts[0] != folder:
        return None
    stripped_parts = path.parts[1:]
    if not stripped_parts:
        return None
    return PurePosixPath(*stripped_parts)


def _validate_required_structure(
    file_paths: set[PurePosixPath], dir_paths: set[PurePosixPath]
) -> None:
    if not REQUIRED_FILES.issubset(file_paths) or not REQUIRED_DIRS.issubset(dir_paths):
        raise CaImportError("Import abgebrochen: Pflichtbestandteile fehlen.")


def _read_ca_common_name(ca_cert: Path) -> str:
    try:
        output = run_openssl_capture(["x509", "-in", str(ca_cert), "-noout", "-subject"]).strip()
    except subprocess.CalledProcessError as exc:
        raise CaImportError("Import abgebrochen: ungültiges CA-Zertifikat.") from exc

    subject = output.removeprefix("subject=").strip()
    for part in subject.split(","):
        part = part.strip()
        if part.startswith("CN="):
            return part.replace("CN=", "", 1).strip()
    return ""


def _derive_slug(target_slug: str | None, top_level_folder: str | None, ca_cert: Path) -> str:
    candidate = (target_slug or "").strip() or (top_level_folder or "").strip()
    if not candidate:
        candidate = _read_ca_common_name(ca_cert)
    safe_slug = secure_filename(candidate)
    if not safe_slug:
        raise CaImportError("Import abgebrochen: ungueltiger CA-Name.")
    return safe_slug


def _key_looks_encrypted(ca_key: Path) -> bool:
    try:
        key_text = ca_key.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        raise CaImportError("Import abgebrochen: privater Key konnte nicht gelesen werden.") from exc
    return "ENCRYPTED" in key_text or "Proc-Type: 4,ENCRYPTED" in key_text


def _extension_text(cert_text: str, extension_name: str) -> str:
    lines = cert_text.splitlines()
    for index, line in enumerate(lines):
        if extension_name not in line:
            continue
        extension_lines = [line]
        for following in lines[index + 1 :]:
            if following.startswith("            X509v3 "):
                break
            extension_lines.append(following)
        return "\n".join(extension_lines)
    return ""


def _validate_ca_certificate_extensions(ca_cert: Path) -> None:
    try:
        cert_text = run_openssl_capture(
            ["x509", "-in", str(ca_cert), "-noout", "-text"]
        )
    except subprocess.CalledProcessError as exc:
        raise CaImportError("Import abgebrochen: ungültiges CA-Zertifikat.") from exc

    basic_constraints = _extension_text(cert_text, "X509v3 Basic Constraints")
    if "CA:TRUE" not in basic_constraints:
        raise CaImportError(
            "Import abgebrochen: CA-Zertifikat ist nicht als CA nutzbar."
        )

    key_usage = _extension_text(cert_text, "X509v3 Key Usage")
    if key_usage and "Certificate Sign" not in key_usage and "keyCertSign" not in key_usage:
        raise CaImportError(
            "Import abgebrochen: CA-Zertifikat darf keine Zertifikate signieren."
        )


def _validate_ca_material(ca_dir: Path) -> None:
    ca_cert = ca_dir / "certs" / "ca.crt"
    ca_key = ca_dir / "private" / "ca.key"
    if _key_looks_encrypted(ca_key):
        raise CaImportError(
            "Import abgebrochen: verschlüsselter Private Key wird nicht unterstützt."
        )

    try:
        cert_pubkey = run_openssl_capture(
            ["x509", "-in", str(ca_cert), "-noout", "-pubkey"]
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise CaImportError("Import abgebrochen: ungültiges CA-Zertifikat.") from exc

    _validate_ca_certificate_extensions(ca_cert)

    try:
        key_pubkey = run_openssl_capture(["pkey", "-in", str(ca_key), "-pubout"]).strip()
    except subprocess.CalledProcessError as exc:
        raise CaImportError("Import abgebrochen: ungültiger privater Key.") from exc

    if cert_pubkey != key_pubkey:
        raise CaImportError("Import abgebrochen: Private Key passt nicht zum CA-Zertifikat.")


def _publish_staging_dir(staging_dir: Path, target_dir: Path) -> None:
    try:
        target_dir.mkdir()
    except FileExistsError as exc:
        raise CaImportError("Import abgebrochen: CA existiert bereits.") from exc
    except OSError as exc:
        raise CaImportError("Import abgebrochen: CA konnte nicht geschrieben werden.") from exc

    try:
        for child in staging_dir.iterdir():
            shutil.move(str(child), str(target_dir / child.name))
        staging_dir.rmdir()
    except (OSError, shutil.Error) as exc:
        if target_dir.exists():
            shutil.rmtree(target_dir)
        raise CaImportError("Import abgebrochen: CA konnte nicht geschrieben werden.") from exc


def import_ca_zip(archive_file: BinaryIO, target_slug: str | None = None) -> str:
    try:
        archive = zipfile.ZipFile(archive_file)
    except zipfile.BadZipFile as exc:
        raise CaImportError("Import abgebrochen: ungueltige ZIP-Datei.") from exc

    with archive:
        zip_members = _safe_zip_members(archive)
        top_level_folder = _top_level_folder([member.path for member in zip_members])
        provisional_slug = secure_filename(target_slug or top_level_folder or "imported-ca")
        if not provisional_slug:
            raise CaImportError("Import abgebrochen: ungueltiger CA-Name.")

        file_map: dict[str, PurePosixPath] = {}
        dir_paths: set[PurePosixPath] = set()
        for member in zip_members:
            relative_target = _strip_top_level(member.path, top_level_folder)
            if relative_target is None:
                continue
            if member.is_dir:
                dir_paths.add(relative_target)
            else:
                file_map[member.name] = relative_target

        _validate_required_structure(set(file_map.values()), dir_paths)

        target_dir = CA_ROOT / provisional_slug
        if (target_slug or top_level_folder) and target_dir.exists():
            raise CaImportError("Import abgebrochen: Ziel-Slug existiert bereits.")

        CA_ROOT.parent.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(
            tempfile.mkdtemp(prefix=f".{provisional_slug}-import-", dir=str(CA_ROOT.parent))
        )
        try:
            for relative_dir in dir_paths:
                (staging_dir / Path(*relative_dir.parts)).mkdir(parents=True, exist_ok=True)
            for source, relative_target in file_map.items():
                destination = staging_dir / Path(*relative_target.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with archive.open(source) as source_file, destination.open("wb") as out_file:
                        shutil.copyfileobj(source_file, out_file)
                except zipfile.BadZipFile as exc:
                    raise CaImportError("Import abgebrochen: ungueltige ZIP-Datei.") from exc

            safe_slug = _derive_slug(
                target_slug, top_level_folder, staging_dir / "certs" / "ca.crt"
            )
            target_dir = CA_ROOT / safe_slug
            if target_dir.exists():
                raise CaImportError("Import abgebrochen: Ziel-Slug existiert bereits.")

            _validate_ca_material(staging_dir)

            ensure_ca_dirs(staging_dir)
            ensure_ca_config(staging_dir)

            CA_ROOT.mkdir(parents=True, exist_ok=True)
            if target_dir.exists():
                raise CaImportError("Import abgebrochen: Ziel-Slug existiert bereits.")
            _publish_staging_dir(staging_dir, target_dir)
            staging_dir = None
        finally:
            if staging_dir is not None and staging_dir.exists():
                shutil.rmtree(staging_dir)

        return safe_slug
