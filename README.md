# Skript-Reihenfolge und Ausführung

### Schritt 1: `01_download_cve_cwe_exploitdb_data.py`
Datenbanken der **CVE-List**, **CWE-List** und **Exploit-DB** herunterladen.

### Schritt 2: `02_convert_cvelist_to_csv.py`
Alle relevanten Daten werden aus der CVE-List (`cve_data.json`) extrahiert und in die CSV-Datei `DATA_02_cvelist_base_filtered.csv` gespeichert.

### Schritt 3: `03_check_and_add_cwe_description.py`
Die zuvor erstellte Datei wird anhand der CWE-List (`cwec_latest.xml`) um die textuelle CWE-Beschreibung ergänzt und in die Datei `DATA_03_cvelist_base_filtered_added_cwe_description.csv` gespeichert.

### Schritt 4: `04_check_and_add_exploit_db_reference.py`
Die Datei wird um Daten aus der Exploit-DB (`files_exploits.csv`) ergänzt und in `DATA_04_cvelist_base_filtered_added_exploitdb_reference.csv` gespeichert.

### Schritt 5: `05_filter_enrich_final_data.py`
**Wichtig:** Vor der Ausführung muss die Datei `keywords.json` im Hauptordner mit Keywords befüllt werden. Die Struktur der Datei muss beibehalten werden, zusätzliche Unterkategorien können hinzugefügt werden.

Dieses Skript erweitert die zuvor erstellte Datei um weitere Daten zu Fehlerklassen, Betriebssystemen und Applikationen. Treffer werden in den jeweiligen Zeilen mit einem **"YES"** gekennzeichnet. 

Zum Schluss muss die Datei `DATA_05_filtered_cvelist_enriched.csv` mit einem Tabellenkalkulationsprogramm nach den gewünschten **"YES"**-Werten gefiltert werden, um die finale Datenmenge an CVEs anzuzeigen.
