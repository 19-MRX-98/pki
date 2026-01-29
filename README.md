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

## Features (Überblick)

- Mehrere CAs mit eigenem Issued-Store
- Zertifikate erstellen, anzeigen (PEM + Details) und herunterladen
- CSR-Import inkl. optionalem Private-Key-Upload
- Zertifikate zurückziehen (CRL) + CRL-Details anzeigen
- Benutzerverwaltung (Login, User anlegen, Passwörter ändern)
- Reverseproxy-Management (VHosts, Defaults, Containerliste)
- Darkmode-Toggle

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

## Zertifikate anzeigen

- Zertifikate lassen sich im Browser mit Rohdaten (PEM) und OpenSSL-Details anzeigen.
- Bei CSR-Importen wird kein Private Key angezeigt (falls keiner hochgeladen wurde).

## Sperrlisten (CRL)

- Für jede CA kann eine CRL erzeugt und heruntergeladen werden.
- Detailansicht listet zurückgezogene Zertifikate (Serial + Revocation Date).

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
- Im Menüpunkt **Reverseproxy** können Defaults gesetzt, VHosts erstellt und bestehende Einträge verwaltet werden.
- Reverseproxy-Seite zeigt vorhandene Domains und lokale Container inkl. Upstream-Vorschlägen.

### Hinweis zu Ports (Variante B)

- Wenn auf dem Host Port 80 belegt ist, kann der Nginx-Container nur HTTPS nach außen exponieren:
  - `8443:443`
- Zugriff erfolgt dann über: `https://<host>:8443`
- Für den ersten Zugriff auf die PKI-App ist im Compose zusätzlich `5000:5000` gemappt,
  damit du Zertifikate erzeugen und die Nginx-Deploy-Funktion nutzen kannst.
  Danach kannst du den Port optional wieder entfernen.

## Docker Compose (Stack)

- `docker-compose.yml` enthält Profile:
  - `proxy`: PKI-App + Nginx Reverseproxy (Port 8443)
  - `standalone`: nur PKI-App ohne Reverseproxy-Funktionen
- Nginx nutzt `./nginx/nginx.conf` und `./nginx/sites-enabled`.
- Zertifikate werden unter `./nginx/certs` abgelegt.
- Starten:
  - Proxy-Stack: `docker compose --profile proxy up -d`
  - Standalone: `docker compose --profile standalone up -d`
- Optional per `.env`: `COMPOSE_PROFILES=proxy` oder `COMPOSE_PROFILES=standalone`,
  dann reicht `docker compose up -d`.
- GHCR-Variante: `docker-compose.ghcr.yml` (zieht `ghcr.io/<owner>/<repo>:latest`)

## Docker Swarm (Stack)

- Datei: `docker-stack.yml` (nur PKI + Reverseproxy, keine Standalone)
- Läuft nur auf Manager-Nodes (constraints)
- Optional: Services auf Leader pinnen via Node-Label:
  - `docker node update --label-add pki-leader=true <LEADER_NODE>`
  - Constraint: `node.labels.pki-leader == true`
- Overlay-Netzwerk: `pki-net`
- Deploy: `docker stack deploy -c docker-stack.yml pki`
- Service-Erkennung erfolgt über Swarm-DNS im Overlay-Netz:
  - Upstream in Nginx sollte `http://pki-app:5000` sein
  - Funktioniert auf allen Nodes, solange beide Services im selben Overlay-Netz sind
- Swarm-Reload:
  - `NGINX_RELOAD_SERVICE=pki-reverseproxy` (Service-Name, kein Container-Name)
- Optionaler Agent (empfohlen für Multi-Node):
  - Image: `ghcr.io/<owner>/<repo>-agent:latest`
  - Service-Name: `nginx-reload-agent` (global)
  - App-ENV: `NGINX_AGENT_URL=http://nginx-reload-agent:9000`
  - Optionales Token: `NGINX_AGENT_TOKEN` + `AGENT_TOKEN`

## GitHub Actions

- Workflow: `.github/workflows/docker-image.yml`
- Baut und veröffentlicht Images nach GHCR (`ghcr.io/<owner>/<repo>`)

## Troubleshooting

**502 Bad Gateway (nginx)**
- Upstream nicht erreichbar oder falsch.
- Im VHost prüfen: `proxy_pass http://pki-app:5000;` (Service-Name statt IP).
- Test im nginx-Container: `docker exec pki-reverseproxy wget -qO- http://pki-app:5000`

**504 Gateway Time-out (nginx)**
- Upstream antwortet nicht rechtzeitig oder Blockade beim Reload/Socket.
- Prüfen, ob die App läuft und im gleichen Docker-Netz hängt.

**Reverseproxy-Seite lädt nicht / Containerliste leer**
- Docker Socket mounten: `/var/run/docker.sock:/var/run/docker.sock`
- Rechte prüfen: `ls -l /var/run/docker.sock`
- Falls Socket Gruppe z. B. `987`: in Compose `group_add: ["987"]`

**Nginx-Deploy: Ungültige Upstream-URL**
- Muss mit `http://` oder `https://` beginnen und keine Leerzeichen enthalten.

**CRL-Fehler**
- Falls `cannot lookup how long until the next CRL is issued`, CA-Config wurde erneuert: neu bauen/reloaden.

## Docker

```bash
docker build -t pki-app .
docker run --rm -p 5000:5000 -e FLASK_SECRET_KEY="bitte-aendern" -v "$(pwd)/data:/app/data" pki-app
```
