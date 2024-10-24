# Skript-Reihenfolge und Ausführung

Anmerkung: Alle Daten werden ausschließlich im Projekt-Hauptverzeichnis geladen und gespeichert.
Der Ablauf ist so konzipiert, dass jedes Skript manuell nacheinander ausgeführt werden muss. Jedes Skript nimmt hierbei das Ergebnis aus dem vorherigen Schritt als Grundlage und erstellt im Ergebnis jeweils eine eigene Ausgabe-Datei.

### Schritt 1: `01_download_cve_cwe_exploitdb_data.py`
Die Daten zur **CVE-List**, **CWE-List** und **Exploit-DB** werden herunterladen. Im Ergebnis hat man hier nun folgende Dateien: (`cve_data.json`), (`cwec_latest.xml`), (`files_exploits.csv`)

### Schritt 2: `02_convert_cvelist_to_csv.py`
Zunächst werden alle relevanten Daten aus der CVE-List (`cve_data.json`) extrahiert und in die neue CSV-Datei `DATA_02_cvelist_base_filtered.csv` gespeichert.

### Schritt 3: `03_check_and_add_cwe_description.py`
Die zuvor erstellte Datei wird anhand der CWE-List (`cwec_latest.xml`) um die textuelle CWE-Beschreibung ergänzt und in die neue Datei `DATA_03_cvelist_base_filtered_added_cwe_description.csv` gespeichert.

### Schritt 4: `04_check_and_add_exploit_db_reference.py`
Die Datei wird um Daten aus der Exploit-DB (`files_exploits.csv`) ergänzt und in die neue Datei `DATA_04_cvelist_base_filtered_added_exploitdb_reference.csv` gespeichert.

### Schritt 5: `05_filter_enrich_final_data.py`
**Wichtig:** Vor der Ausführung muss die Datei `keywords.json` im Projektordner mit Keywords befüllt werden. Die Struktur der Datei muss beibehalten werden (3 Oberkategorieren `desktop_software`, `server_software` und `custom_software` mit jeweils mind. 1 Unterkategorie). Zusätzliche Unterkategorien können hinzugefügt werden.

Dieses Skript erweitert die zuvor erstellte Datei um weitere Daten zu den Fehlerklassen, Betriebssystemen und Applikationen. Hierfür werden separate Spalten erstellt. Treffer werden in den jeweiligen Zeilen mit einem **"YES"** gekennzeichnet. 

Zum Schluss muss die Datei `DATA_05_filtered_cvelist_enriched.csv` mit einem Tabellenkalkulationsprogramm nach den gewünschten **"YES"**-Werten gefiltert werden, um die finale Datenmenge an CVEs anzuzeigen.
