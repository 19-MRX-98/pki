# CA ZIP Import Design

## Ziel

Die PKI-App soll eine bestehende Zertifizierungsstelle aus einem ZIP-Backup vollständig importieren. Der Import soll sich wie ein Restore eines CA-Backups verhalten: CA-Zertifikat, privater CA-Key, OpenSSL-Datenbank, Serial-/CRL-Zähler, Newcerts und CRL-Daten werden gemeinsam übernommen.

## Eingabeformat

Der Import akzeptiert ein ZIP-Archiv im App-kompatiblen CA-Format. Das Archiv darf die CA-Dateien direkt im ZIP-Root enthalten oder einen einzelnen Top-Level-Ordner enthalten, der die CA-Dateien enthält.

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

Wenn `openssl.cnf` enthalten ist, wird sie nicht blind weiterverwendet. Nach dem Import schreibt die App ihre kompatible OpenSSL-Konfiguration neu, damit absolute Pfade auf den neuen Speicherort zeigen.

## Slug und Konflikte

Der Nutzer kann beim Import optional einen Ziel-Kurznamen angeben. Wenn kein Kurzname angegeben ist, wird der einzelne Top-Level-Ordner im ZIP als Basis verwendet. Enthält das ZIP die Dateien direkt im Root, verwendet die App den Common Name des CA-Zertifikats als Basis.

Der resultierende Slug wird mit der bestehenden `secure_filename`-Logik normalisiert. Wenn unter `data/ca/<slug>` bereits eine CA existiert, bricht der Import ab. Es wird nichts überschrieben und keine automatische Umbenennung vorgenommen.

## Validierung und Importablauf

Der Import arbeitet in einem temporären Verzeichnis und verschiebt die CA erst nach vollständiger Validierung nach `data/ca/<slug>`.

Validierungsschritte:

1. ZIP sicher entpacken und Pfad-Traversal verhindern.
2. Archivstruktur normalisieren: Root-Dateien oder genau einen Top-Level-Ordner akzeptieren.
3. Pflichtdateien und Pflichtordner prüfen.
4. CA-Zertifikat mit OpenSSL lesen.
5. Privaten CA-Key mit OpenSSL lesen.
6. Prüfen, dass der Private Key zum CA-Zertifikat passt.
7. Verschlüsselte Private Keys ablehnen, weil die vorhandenen Signatur- und CRL-Flows keine Passphrase verarbeiten.
8. App-kompatible CA-Verzeichnisse und OpenSSL-Konfiguration sicherstellen.
9. Vor dem finalen Verschieben erneut prüfen, dass der Ziel-Slug noch nicht existiert.
10. Vorbereitete CA atomar nach `data/ca/<slug>` verschieben.

## Verhalten nach dem Import

Nach erfolgreichem Import erscheint die CA in der vorhandenen CA-Liste. Die bestehenden Funktionen zum Ausstellen von Zertifikaten, Erzeugen und Herunterladen von CRLs sowie Enrollment verwenden die importierte CA-Struktur unverändert weiter.

Bereits ausgestellte Zertifikate aus dem importierten OpenSSL-Backup bleiben in `index.txt` und `newcerts/` erhalten und können damit für OpenSSL-gestützte CRL-Operationen relevant bleiben. Sie erscheinen nicht automatisch in der App-Liste unter `data/issued/<ca-slug>/`, weil diese Ansicht aktuell nur den separaten App-Issued-Store auswertet. Ein Import oder eine Rekonstruktion dieser UI-Liste ist nicht Teil dieser ersten Funktion.

## Fehlerbehandlung

Fehler werden auf der CA-Seite als klare Flash-Meldungen angezeigt. Relevante Fehlerfälle:

- ungültiges oder nicht lesbares ZIP-Archiv
- unsichere ZIP-Pfade
- mehrere unerwartete Top-Level-Ordner
- fehlende Pflichtdateien oder Pflichtordner
- leerer oder ungültiger Slug
- Ziel-Slug existiert bereits
- ungültiges CA-Zertifikat
- ungültiger privater Key
- Private Key passt nicht zum CA-Zertifikat
- verschlüsselter Private Key
- Import konnte nicht geschrieben oder final verschoben werden

## UI

Die Seite `Zertifizierungsstellen` erhält neben dem Formular zum Erstellen einer neuen CA einen Abschnitt `CA-Backup importieren`. Das Formular enthält einen ZIP-Dateiupload und ein optionales Feld für den Ziel-Kurznamen. Nach Erfolg leitet die App auf die CA-Seite mit der importierten CA als Auswahl weiter.

## Tests

Automatisierte Tests sollen die Importlogik auf Modulebene und die Route mit Flask-Testclient abdecken.

Testfälle:

- gültiges ZIP importiert eine CA und `list_cas()` zeigt sie an
- existierender Slug bricht ab und lässt die vorhandene CA unverändert
- ZIP mit Pfad-Traversal wird abgelehnt
- ZIP mit fehlenden Pflichtbestandteilen wird abgelehnt
- nicht passender Private Key wird abgelehnt
- verschlüsselter Private Key wird abgelehnt
- ZIP mit einzelnem Top-Level-Ordner und ZIP mit Dateien im Root werden akzeptiert

## Nicht-Ziele

- Kein Überschreiben bestehender CAs
- Keine automatische Slug-Umbenennung
- Keine Unterstützung für passwortgeschützte CA-Keys
- Kein automatischer Import bereits ausgestellter Zertifikate in `data/issued/<ca-slug>/`
- Kein generischer Import beliebiger fremder OpenSSL-Verzeichnislayouts außerhalb der beschriebenen ZIP-Struktur
