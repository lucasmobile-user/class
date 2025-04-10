import subprocess
import xml.etree.ElementTree as ET
import requests
import tempfile
import os
import sys

def get_cve_info(service, version):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}+{version}"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        if data.get('totalResults', 0) > 0:
            cve = data['vulnerabilities'][0]['cve']
            return {
                'id': cve['id'],
                'description': cve['descriptions'][0]['value'][:100] + "..."
            }
        return {'id': 'Nenhum CVE encontrado', 'description': 'Sem vulnerabilidades conhecidas.'}
    except Exception as e:
        return {'id': 'Erro', 'description': f'Falha na API: {str(e)}'}

def run_nmap(target):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmpfile:
        try:
            subprocess.run(['nmap', '-sV', '-oX', tmpfile.name, target], check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Erro ao executar o Nmap: {e}")
            sys.exit(1)

        tmpfile.seek(0)
        return tmpfile.name

def parse_nmap_output(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    os.remove(xml_file)  # Limpa o arquivo temporário

    vulnerabilities = []
    for port in root.findall('.//port'):
        service = port.find('service')
        if service is not None:
            port_id = port.get('portid')
            service_name = service.get('name', 'desconhecido')
            version = service.get('version', 'desconhecida')
            cve_info = get_cve_info(service_name, version)
            vulnerabilities.append({
                'port': port_id,
                'service': service_name,
                'version': version,
                'cve_id': cve_info['id'],
                'cve_desc': cve_info['description']
            })
    return vulnerabilities

def main():
    print("🛡️  Scanner de Serviços + Consulta de CVEs")
    target = input("Digite o IP ou domínio a ser analisado: ").strip()

    if not target:
        print("[!] Alvo inválido.")
        return

    print(f"\n[~] Escaneando {target}...\n")
    xml_file = run_nmap(target)
    results = parse_nmap_output(xml_file)

    print(f"\n🔍 Resultados para {target}:\n")
    for item in results:
        print(f"[Porta {item['port']}] {item['service']} ({item['version']})")
        print(f"  CVE: {item['cve_id']}")
        print(f"  Desc: {item['cve_desc']}\n")

if __name__ == '__main__':
    main()
