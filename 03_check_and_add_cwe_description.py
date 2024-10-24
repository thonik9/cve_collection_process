import csv
import xml.etree.ElementTree as ET
from tqdm import tqdm

def enrich_with_cwe_descriptions(input_csv, output_csv, cwe_xml_filename):
    # Parsen der CWE-XML-Datei
    tree = ET.parse(cwe_xml_filename)
    root = tree.getroot()
    
    # Namespace für die XML-Verarbeitung
    ns = {'ns': 'http://cwe.mitre.org/cwe-7'}
    
    cwe_descriptions = {}
    
    # Durchlaufen der Weakness-Elemente
    for weakness in root.findall('.//ns:Weakness', ns):
        cwe_id = weakness.get('ID')
        name = weakness.get('Name')
        cwe_descriptions[cwe_id] = name

    # Öffnen der CSV-Dateien zum Lesen und Schreiben
    with open(input_csv, 'r', newline='', encoding='utf-8') as infile, open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames
        fieldnames.append('CWE Descriptions')

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        # Fortschrittsbalken initialisieren
        with tqdm(total=sum(1 for row in reader), desc="Anreicherung", unit="CVE", ncols=100) as pbar:
            infile.seek(0)
            next(reader)  # Skip header row

            for row in reader:
                cwe_ids = row['CWE IDs'].split('; ')
                cwe_descriptions_list = []

                for cwe_id in cwe_ids:
                    if cwe_id in ['NVD-CWE-Other', 'NVD-CWE-noinfo']:
                        continue

                    description = cwe_descriptions.get(cwe_id, None)
                    if not description:
                        # Durchlaufen der Category-Elemente, wenn in Weakness nichts gefunden wurde
                        for category in root.findall('.//ns:Category', ns):
                            if category.get('ID') == cwe_id:
                                description = category.get('Name')
                                break
                    cwe_descriptions_list.append(description if description else 'N/A')

                row['CWE Descriptions'] = "; ".join(cwe_descriptions_list)
                writer.writerow(row)
                pbar.update(1)

# Beispielaufruf der Funktion
enrich_with_cwe_descriptions('DATA_02_cvelist_base_filtered.csv', 'DATA_03_cvelist_base_filtered_added_cwe_description.csv', 'cwec_latest.xml')
