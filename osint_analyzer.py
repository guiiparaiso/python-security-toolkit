import json
import os
from datetime import datetime
from colorama import Fore, Style, init
import requests
from tabulate import tabulate

init(autoreset=True)


class OSINTAnalyzer:

    def __init__(self, target_input: str):
        cleaned = (
            target_input.strip()
            .lower()
            .replace("https://", "")
            .replace("http://", "")
        )
        self.domain = cleaned.split("/")[0]

        self.report_data = {
            "target": self.domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip_info": {},
            "dns_records": {},
            "subdomains": [],
        }

    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║                OSINT AUTOMATED RECON                 ║
║          Portfolio Security Script - Python          ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
        print(
            f"{Fore.YELLOW}[*] Alvo configurado: {Style.BRIGHT}{self.domain}{Style.RESET_ALL}\n"
        )

    def fetch_ip_and_location(self):
        print(
            f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Consultando geolocalização e infraestrutura IP..."
        )
        url = f"http://ip-api.com/json/{self.domain}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                self.report_data["ip_info"] = {
                    "ip": data.get("query"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "country": data.get("country"),
                    "city": data.get("city"),
                }
                print(
                    f"{Fore.GREEN}[SUCESSO]{Style.RESET_ALL} IP mapeado: {data.get('query')}"
                )
            else:
                self.report_data["ip_info"] = {"erro": "Domínio não resolvido"}
                print(
                    f"{Fore.RED}[ERRO]{Style.RESET_ALL} Domínio não encontrado."
                )
        except requests.exceptions.RequestException as e:
            self.report_data["ip_info"] = {
                "erro": f"Falha na requisição: {str(e)}"
            }
            print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} Falha na conexão com a API.")

    def fetch_dns_records(self):
        print(
            f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Coletando registros DNS (Google DoH)..."
        )
        dns_types = ["A", "MX", "NS", "TXT"]
        dns_results = {}

        for r_type in dns_types:
            url = f"https://dns.google/resolve?name={self.domain}&type={r_type}"
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()

                if "Answer" in data:
                    records = [
                        item["data"]
                        for item in data["Answer"]
                        if "data" in item
                    ]
                    dns_results[r_type] = records
                else:
                    dns_results[r_type] = ["Nenhum registro encontrado"]
            except requests.exceptions.RequestException:
                dns_results[r_type] = ["Erro na consulta"]

        self.report_data["dns_records"] = dns_results
        print(
            f"{Fore.GREEN}[SUCESSO]{Style.RESET_ALL} Registros DNS mapeados com sucesso."
        )

    def fetch_subdomains(self):
        print(
            f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Buscando subdomínios via transparência de certificados..."
        )
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()

            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                names = name_value.split("\n")
                for name in names:
                    if name.endswith(self.domain) and not name.startswith("*"):
                        subdomains.add(name)

            self.report_data["subdomains"] = sorted(list(subdomains))[:15]
            print(
                f"{Fore.GREEN}[SUCESSO]{Style.RESET_ALL} {len(self.report_data['subdomains'])} subdomínios principais encontrados."
            )
        except requests.exceptions.RequestException:
            self.report_data["subdomains"] = [
                "Não foi possível recuperar os subdomínios"
            ]
            print(
                f"{Fore.RED}[AVISO]{Style.RESET_ALL} Falha ao consultar subdomínios."
            )

    def display_cli_summary(self):
        ip_info = self.report_data["ip_info"]
        table_data = [
            ["Endereço IP", ip_info.get("ip", "N/A")],
            ["Provedor (ISP)", ip_info.get("isp", "N/A")],
            ["Organização", ip_info.get("org", "N/A")],
            ["Localização", f"{ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}"],
        ]
        print("\n" + "=" * 50)
        print(f"{Fore.CYAN} RESUMO DA ANÁLISE DE INFRAESTRUTURA{Style.RESET_ALL}")
        print("=" * 50)
        print(
            tabulate(
                table_data, headers=["Métrica", "Detalhe"], tablefmt="fancy_grid"
            )
        )

    def generate_markdown_report(self):
        filename = f"report_{self.domain.replace('.', '_')}.md"
        print(
            f"\n{Fore.BLUE}[INFO]{Style.RESET_ALL} Gerando relatório estruturado em Markdown..."
        )

        ip_info = self.report_data["ip_info"]

        md_content = f"""# 🛡️ Relatório Técnico de Reconhecimento OSINT
**Alvo Analisado:** `{self.report_data['target']}`  
**Data e Hora da Varredura:** `{self.report_data['timestamp']}`  
**Status da Ferramenta:** Concluído com Sucesso  

---

## 🌐 1. Infraestrutura de Rede e Geolocalização

| Parâmetro de Rede | Ativo / Detalhe Técnico |
| :--- | :--- |
| **Endereço IP Principal** | `{ip_info.get('ip', 'N/A')}` |
| **Provedor de Serviços (ISP)** | {ip_info.get('isp', 'N/A')} |
| **Organização Registrada** | {ip_info.get('org', 'N/A')} |
| **Localização Geográfica** | {ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')} |

---

## 📡 2. Mapeamento de Registros DNS

"""
        for r_type, records in self.report_data["dns_records"].items():
            md_content += f"### Registro `{r_type}`\n"
            for record in records:
                md_content += f"- `{record}`\n"
            md_content += "\n"

        md_content += """---

## 🔗 3. Subdomínios Descobertos (Certificates Transparency)

"""
        if self.report_data["subdomains"]:
            for sub in self.report_data["subdomains"]:
                md_content += f"- `{sub}`\n"
        else:
            md_content += "Nenhum subdomínio mapeado.\n"

        md_content += "\n---  \n*Relatório gerado automaticamente por script OSINT Python desenvolvido para fins de portfólio de cibersegurança.*\n"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(md_content)

        print(
            f"{Fore.GREEN}[SUCESSO]{Style.RESET_ALL} Relatório gravado com sucesso no arquivo: {Style.BRIGHT}{filename}{Style.RESET_ALL}"
        )


def run_osint():
    target = input(
        f"{Fore.YELLOW}[?] Digite o domínio alvo (ex: target.com): {Style.RESET_ALL}"
    ).strip()
    if target:
        analyzer = OSINTAnalyzer(target)
        analyzer.print_banner()
        analyzer.fetch_ip_and_location()
        analyzer.fetch_dns_records()
        analyzer.fetch_subdomains()
        analyzer.display_cli_summary()
        analyzer.generate_markdown_report()
        print(f"\n{Fore.GREEN}[+] Execução finalizada com êxito.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] Entrada inválida fornecida.{Style.RESET_ALL}")

    input(
        f"\n{Fore.DIM}Pressione ENTER para retornar ao menu principal...{Style.RESET_ALL}"
    )