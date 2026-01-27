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

## Docker

```bash
docker build -t pki-app .
docker run --rm -p 5000:5000 -e FLASK_SECRET_KEY="bitte-aendern" -v "$(pwd)/data:/app/data" pki-app
```
