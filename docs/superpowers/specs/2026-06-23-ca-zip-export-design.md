# CA ZIP Export Design

## Ziel

Die PKI-App soll eine bestehende Zertifizierungsstelle als vollständiges, unverschlüsseltes ZIP-Backup exportieren. Das Backup soll direkt mit dem vorhandenen CA-ZIP-Import wiederherstellbar sein.

## Exportumfang

Der Export erzeugt ein ZIP-Archiv mit der CA-Struktur relativ zum CA-Root.

Pflichtbestandteile:

- `certs/ca.crt`
- `private/ca.key`
- `index.txt`
- `serial`
- `crlnumber`
- `newcerts/`
- `crl/`

Optional:

- `openssl.cnf`
- vorhandene Dateien unter `newcerts/` und `crl/`

Der private CA-Key ist ausdrücklich Teil des Backups. Das ZIP wird nicht verschlüsselt.

## UI und Route

Die Seite `Zertifizierungsstellen` erhält pro CA einen zusätzlichen Download-Button `CA-Backup`. Der Button ruft eine neue Route `GET /ca/<slug>/backup` auf.

Die Route prüft:

1. Storage ist vorbereitet.
2. Die CA existiert.
3. Die Pflichtbestandteile sind vorhanden.
4. Das ZIP kann erzeugt werden.

Bei Erfolg liefert die Route ein ZIP mit einem Dateinamen wie `<slug>-ca-backup.zip`.

## Fehlerbehandlung

Fehler werden auf der CA-Seite als Flash-Meldungen angezeigt.

Relevante Fehlerfälle:

- CA nicht gefunden
- CA ist unvollständig und kann nicht als vollständiges Restore-Backup exportiert werden
- Backup-ZIP konnte nicht erzeugt oder gelesen werden

Ein unvollständiges Backup wird nicht ausgeliefert.

## Sicherheitsverhalten

Der Export ist nur für eingeloggte Nutzer verfügbar, wie die bestehende CA-Seite und andere CA-Downloads. Das ZIP enthält den privaten CA-Schlüssel und muss außerhalb der App sicher abgelegt werden. Es wird bewusst keine ZIP-Verschlüsselung verwendet.

## Tests

Automatisierte Tests sollen die Exportlogik und Route abdecken.

Testfälle:

- gültige CA erzeugt ein ZIP mit allen Pflichtbestandteilen inklusive `private/ca.key`
- exportiertes ZIP ist vom vorhandenen Import-Modul akzeptierbar
- unvollständige CA wird abgelehnt
- Route liefert `application/zip` und einen sinnvollen Download-Dateinamen
- Route für fehlende CA zeigt Fehler und leitet zur CA-Seite zurück

## Nicht-Ziele

- Keine Verschlüsselung des ZIP-Backups
- Kein selektiver Export ohne privaten CA-Key
- Kein Export der separaten App-Issued-Liste unter `data/issued/<ca-slug>/`
- Kein globales Backup aller CAs in einem Archiv
