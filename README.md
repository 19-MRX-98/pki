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

## Docker

```bash
docker build -t pki-app .
docker run --rm -p 5000:5000 -e FLASK_SECRET_KEY="bitte-aendern" -v "$(pwd)/data:/app/data" pki-app
```
