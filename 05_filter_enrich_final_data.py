import csv
import json
import pandas as pd
from tqdm import tqdm
import requests
from bs4 import BeautifulSoup
import re

# Funktion, um den Text zu bereinigen
def clean_text(text):
    text = re.sub(r'[^a-zA-Z0-9\s-]', '', text)
    text = text.replace('\n', ' ').replace('\r', ' ')
    return text.lower()

# Funktion, um die Keywords aus der Datei 'keywords.json' zu laden
def load_keywords(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        keywords = json.load(file)
    return keywords

# Einlesen der keywords
keywords = load_keywords('keywords.json')
desktop_software_keywords = keywords['desktop_software']
server_software_keywords = keywords['server_software']
custom_software_keywords = keywords['custom_software']

# Schlüsselwörter für verschiedene Betriebssysteme
os_keywords = {
    'Windows': ['windows', 'win'],
    'Linux': ['linux', 'ubuntu', 'debian', 'centos', 'redhat', 'fedora', 'suse', 'opensuse', 'arch'],
    'MacOS': ['macos', 'osx', 'mac_os']
}

# Fehlerklassen-Keywords
error_class_keywords = {
    'Remote Code Execution': ['remote code execution'],
    'Privilege Escalation': ['privilege escalation'],
    'Command Injection': ['command injection'],
    'Denial of Service': ['denial of service'],
    'Buffer Overflow': ['buffer overflow'],
    'Memory Corruption': ['memory corruption'],
    'Cross-Site Scripting': ['cross site scripting', 'xss'],
    'Information Disclosure': ['information disclosure']
}

# Funktion, um die Applikations-Kategorie basierend auf dem CPE-Namen zu bestimmen
def categorize_cpe_software(cpe_name):
    categories = []
    cpe_parts = cpe_name.split(':')
    if len(cpe_parts) > 4:
        product_name = cpe_parts[4].lower()  # Convert to lower case for case-insensitive matching
    else:
        product_name = ''
    if 'o:' in cpe_name:
        categories.append('Operating Systems')
    elif 'a:' in cpe_name:
        for category, keyword_list in desktop_software_keywords.items():
            if product_name in map(str.lower, keyword_list):
                categories.append('Desktop Software')
                categories.append(category)
        for category, keyword_list in server_software_keywords.items():
            if product_name in map(str.lower, keyword_list):
                categories.append('Server Software')
                categories.append(category)
        for category, keyword_list in custom_software_keywords.items():
            if product_name in map(str.lower, keyword_list):
                categories.append('Custom Software')
                categories.append(category)
        # Prüfung auf das Betriebssystem basierend auf dem CPE-Namen
        if len(cpe_parts) > 10 and cpe_parts[10] != '*':
            categories.append('Operating Systems')
    elif 'h:' in cpe_name:
        categories.append('Hardware')
    if 'a:' in cpe_name:
        categories.append('Application Software')

    return categories

# Funktion, um das Betriebssystem basierend auf dem CPE-Namen zu bestimmen
def determine_os(cpe_name):
    detected_os = set()
    for os, keywords in os_keywords.items():
        if any(kw in cpe_name for kw in keywords):
            detected_os.add(os)
    return detected_os

# Funktion, um das Betriebssystem basierend auf der Beschreibung zu bestimmen
def detect_os_from_description(description):
    detected_os = set()
    words = description.lower().split()  # Beschreibung in einzelne Wörter aufteilen und alles in Kleinbuchstaben umwandeln
    for os, keywords in os_keywords.items():
        for keyword in keywords:
            if keyword in words:  # Prüfen, ob das exakte Wort in der Liste der Wörter enthalten ist
                detected_os.add(os)
                break
    return detected_os

# Funktion, um die Fehlerklassen in der Beschreibung zu finden
def find_error_classes(description):
    found_classes = set()
    cleaned_description = clean_text(description)
    for error_class, keywords in error_class_keywords.items():
        for keyword in keywords:
            if keyword in cleaned_description:
                found_classes.add(error_class)
    return found_classes

# Funktion, um die lokale CSV-Datei zu filtern und in eine neue CSV-Datei zu speichern
def filter_local_cves(input_filename, output_filename):
    df = pd.read_csv(input_filename, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, skipinitialspace=True)

    # Füge Spalten für Betriebssysteme und Kategorien hinzu
    for os in os_keywords:
        df[os] = ''
    
    categories = ['Operating Systems', 'Desktop Software', 'Server Software', 'Application Software', 'Hardware', 'Custom Software']
    for category in categories:
        df[category] = ''
    
    # Initialisiere den Fortschrittsbalken
    with tqdm(total=len(df), desc="Verarbeitung", unit="CVE", ncols=100) as pbar:
        filtered_rows = []
        for index, row in df.iterrows():

            # Prüfen, ob V3 vorhanden ist und Attack Vector nicht "physical" ist
            if pd.isna(row['CVSS V3 Score']) or  'PHYSICAL' in row['CVSS V3 Attack Vector']:
                pbar.update(1)
                continue
            
            cpe_list = row['CPEs']
            if pd.isna(cpe_list):
                cpe_list = []
            else:
                cpe_list = cpe_list.split(';')  # assuming CPEs are semi-colon separated

            operating_systems = set()
            detected_categories = set()
            description_error_classes = set()

            # Alle CPEs durchsuchen
            for cpe_name in cpe_list:
                categories = categorize_cpe_software(cpe_name)
                detected_categories.update(categories)
                if 'Operating Systems' in categories:
                    os_detected = determine_os(cpe_name)
                    operating_systems.update(os_detected)
            
            # Betriebssysteme aus Beschreibung extrahieren
            if 'Description' in row and pd.notna(row['Description']):
                os_from_description = detect_os_from_description(row['Description'])
                operating_systems.update(os_from_description)

            #Fehlerklassen in der CWE-Beschreibung finden
            if 'CWE Descriptions' in row and pd.notna(row['CWE Descriptions']):
                cwe_description = row['CWE Descriptions']
                cwe_description = clean_text(cwe_description)
                cwe_error_classes = find_error_classes(cwe_description)
                description_error_classes.update(cwe_error_classes)

            # Wenn keine Fehlerklassen in der CWE-Beschreibung gefunden wurden, Fehlerklassen in der Beschreibung finden
            if not description_error_classes and 'Description' in row and pd.notna(row['Description']):
                description = row['Description']
                description = clean_text(description)
                description_error_classes = find_error_classes(description)

            # Setze die Betriebssysteme in der DataFrame
            for os in operating_systems:
                row[os] = 'Yes'
            
            # Setze die Kategorien in der DataFrame
            for category in detected_categories:
                row[category] = 'Yes'
            
            # Setze die gefundenen Fehlerklassen in der DataFrame
            all_error_classes = description_error_classes
            if all_error_classes:
                row['Fehlerklassen'] = ', '.join(all_error_classes)  

            filtered_rows.append(row)
            pbar.update(1)
    
    filtered_df = pd.DataFrame(filtered_rows)

    filtered_df.to_csv(output_filename, index=False, quoting=csv.QUOTE_NONNUMERIC)
    print(f"Die gefilterten Daten wurden erfolgreich in {output_filename} gespeichert.")

if __name__ == '__main__':
    input_filename = 'DATA_04_cvelist_base_filtered_added_exploitdb_reference.csv'  # die ursprüngliche Datei mit allen CVEs
    output_filename = 'DATA_05_filtered_cvelist_enriched.csv'  # die gefilterte Ausgabe-Datei
    filter_local_cves(input_filename, output_filename)
