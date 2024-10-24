import csv
import json
from tqdm import tqdm

# Funktion zum Kürzen des Textes, wenn er eine bestimmte Länge überschreitet
def truncate(text, max_length):
    return text if len(text) <= max_length else text[:max_length]

# Funktion, um den CVSS V3.1- oder CVSS V3.0-Score zu extrahieren
def get_cvss_v3_data(metrics, max_length):
    cvss_v3_score = str(metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'))
    cvss_v3_vector = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('vectorString', 'N/A')
    cvss_v3_severity = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'N/A')
    cvss_v3_impact_score = str(metrics.get('cvssMetricV31', [{}])[0].get('impactScore', 'N/A'))
    cvss_v3_exploitability_score = str(metrics.get('cvssMetricV31', [{}])[0].get('exploitabilityScore', 'N/A'))
    cvss_v3_attack_vector = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('attackVector', 'N/A')
    cvss_v3_attack_complexity = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('attackComplexity', 'N/A')
    cvss_v3_privileges_required = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('privilegesRequired', 'N/A')
    cvss_v3_user_interaction = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('userInteraction', 'N/A')
    cvss_v3_scope = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('scope', 'N/A')
    cvss_v3_confidentiality_impact = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('confidentialityImpact', 'N/A')
    cvss_v3_integrity_impact = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('integrityImpact', 'N/A')
    cvss_v3_availability_impact = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('availabilityImpact', 'N/A')
    cvss_v3_source = metrics.get('cvssMetricV31', [{}])[0].get('source', 'N/A')

    if cvss_v3_score == 'N/A':
        cvss_v3_score = str(metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'))
        cvss_v3_vector = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('vectorString', 'N/A')
        cvss_v3_severity = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('baseSeverity', 'N/A')
        cvss_v3_impact_score = str(metrics.get('cvssMetricV30', [{}])[0].get('impactScore', 'N/A'))
        cvss_v3_exploitability_score = str(metrics.get('cvssMetricV30', [{}])[0].get('exploitabilityScore', 'N/A'))
        cvss_v3_attack_vector = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('attackVector', 'N/A')
        cvss_v3_attack_complexity = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('attackComplexity', 'N/A')
        cvss_v3_privileges_required = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('privilegesRequired', 'N/A')
        cvss_v3_user_interaction = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('userInteraction', 'N/A')
        cvss_v3_scope = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('scope', 'N/A')
        cvss_v3_confidentiality_impact = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('confidentialityImpact', 'N/A')
        cvss_v3_integrity_impact = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('integrityImpact', 'N/A')
        cvss_v3_availability_impact = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('availabilityImpact', 'N/A')
        cvss_v3_source = metrics.get('cvssMetricV30', [{}])[0].get('source', 'N/A')

    return {
        'cvss_v3_score': cvss_v3_score,
        'cvss_v3_vector': cvss_v3_vector,
        'cvss_v3_severity': cvss_v3_severity,
        'cvss_v3_impact_score': cvss_v3_impact_score,
        'cvss_v3_exploitability_score': cvss_v3_exploitability_score,
        'cvss_v3_attack_vector': cvss_v3_attack_vector,
        'cvss_v3_attack_complexity': cvss_v3_attack_complexity,
        'cvss_v3_privileges_required': cvss_v3_privileges_required,
        'cvss_v3_user_interaction': cvss_v3_user_interaction,
        'cvss_v3_scope': cvss_v3_scope,
        'cvss_v3_confidentiality_impact': cvss_v3_confidentiality_impact,
        'cvss_v3_integrity_impact': cvss_v3_integrity_impact,
        'cvss_v3_availability_impact': cvss_v3_availability_impact,
        'cvss_v3_source': cvss_v3_source
    }

def save_all_cves_to_csv_from_json(json_filename, csv_filename):
    max_length = 30000

    # Laden der JSON-Daten
    with open(json_filename, 'r', encoding='utf-8', errors='replace') as json_file:
        cve_data = json.load(json_file)

    total_entries = len(cve_data)
    
    if total_entries > 0:
        # Öffnen der CSV-Datei zum Schreiben
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            headers = [
                'CVE ID', 'Description', 'Published Date', 'Last Modified Date',
                'CVSS V3 Score', 'CVSS V3 Vector', 'CVSS V3 Severity', 'CVSS V3 Impact Score', 'CVSS V3 Exploitability Score',
                'CVSS V3 Attack Vector', 'CVSS V3 Attack Complexity', 'CVSS V3 Privileges Required', 'CVSS V3 User Interaction',
                'CVSS V3 Scope', 'CVSS V3 Confidentiality Impact', 'CVSS V3 Integrity Impact', 'CVSS V3 Availability Impact',
                'CVSS V3 Source', 'References', 'CPEs', 'CWE IDs'
            ]
            writer.writerow(headers)
            
            # Fortschrittsbalken initialisieren
            with tqdm(total=total_entries, desc="Verarbeitung", unit="CVE", ncols=100) as pbar:
                for index, item in enumerate(cve_data):
                    cve = item['cve']
                    cve_id = truncate(cve.get('id', 'N/A'), max_length)
                    description = truncate(cve['descriptions'][0].get('value', 'N/A'), max_length) if 'descriptions' in cve else 'N/A'
                    published_date = truncate(cve.get('published', 'N/A'), max_length)
                    last_modified_date = truncate(cve.get('lastModified', 'N/A'), max_length)
                    
                    metrics = cve.get('metrics', {})
                    cvss_v3_data = get_cvss_v3_data(metrics, max_length)

                    cvss_v3_score = cvss_v3_data['cvss_v3_score']
                    cvss_v3_attack_vector = cvss_v3_data['cvss_v3_attack_vector']

                    # Überprüfen, ob der CVE-Datensatz übersprungen werden sollte
                    if cvss_v3_score == 'N/A' or 'PHYSICAL' in cvss_v3_attack_vector or 'Rejected reason:' in description:
                        pbar.update(1)
                        continue

                    cvss_v3_score = cvss_v3_data['cvss_v3_score']
                    cvss_v3_vector = cvss_v3_data['cvss_v3_vector']
                    cvss_v3_severity = cvss_v3_data['cvss_v3_severity']
                    cvss_v3_impact_score = cvss_v3_data['cvss_v3_impact_score']
                    cvss_v3_exploitability_score = cvss_v3_data['cvss_v3_exploitability_score']
                    cvss_v3_attack_vector = cvss_v3_data['cvss_v3_attack_vector']
                    cvss_v3_attack_complexity = cvss_v3_data['cvss_v3_attack_complexity']
                    cvss_v3_privileges_required = cvss_v3_data['cvss_v3_privileges_required']
                    cvss_v3_user_interaction = cvss_v3_data['cvss_v3_user_interaction']
                    cvss_v3_scope = cvss_v3_data['cvss_v3_scope']
                    cvss_v3_confidentiality_impact = cvss_v3_data['cvss_v3_confidentiality_impact']
                    cvss_v3_integrity_impact = cvss_v3_data['cvss_v3_integrity_impact']
                    cvss_v3_availability_impact = cvss_v3_data['cvss_v3_availability_impact']
                    cvss_v3_source = cvss_v3_data['cvss_v3_source']

                    # Referenzen
                    references = []
                    if 'references' in cve:
                        references = [truncate(ref['url'], max_length) for ref in cve['references']]
                    references_str = truncate("; ".join(references), max_length)

                    # CPEs
                    cpes = []
                    if 'configurations' in cve:
                        for config in cve['configurations']:
                            for node in config.get('nodes', []):
                                for cpe_match in node.get('cpeMatch', []):
                                    cpes.append(truncate(cpe_match['criteria'], max_length))
                    cpes_str = truncate("; ".join(cpes), max_length)

                    # CWE IDs
                    cwe_ids = set()
                    if 'weaknesses' in cve and cve['weaknesses']:
                        for cwe in cve['weaknesses']:
                            potential_cwe_id = cwe.get('description', [{}])[0].get('value', 'N/A')
                            if potential_cwe_id.startswith("CWE-"):
                                potential_cwe_id = potential_cwe_id[4:]  # Entfernt das "CWE-" Präfix
                            if potential_cwe_id != "NVD-CWE-Other":
                                cwe_ids.add(potential_cwe_id)
                        if not cwe_ids:
                            cwe_ids.add("NVD-CWE-Other")

                    cwe_ids_str = truncate("; ".join(cwe_ids), max_length)

                    writer.writerow([
                        cve_id, description, published_date, last_modified_date,
                        cvss_v3_score, cvss_v3_vector, cvss_v3_severity, cvss_v3_impact_score, cvss_v3_exploitability_score,
                        cvss_v3_attack_vector, cvss_v3_attack_complexity, cvss_v3_privileges_required, cvss_v3_user_interaction,
                        cvss_v3_scope, cvss_v3_confidentiality_impact, cvss_v3_integrity_impact, cvss_v3_availability_impact,
                        cvss_v3_source, references_str, cpes_str, cwe_ids_str
                    ])

                    pbar.update(1)

        print(f"Die Daten wurden erfolgreich in {csv_filename} gespeichert.")
    else:
        print("Keine CVE-Daten gefunden.")

# Beispielaufruf der Funktion
save_all_cves_to_csv_from_json("cve_data.json", 'DATA_02_cvelist_base_filtered.csv')

