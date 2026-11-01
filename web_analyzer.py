import argparse
import json
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def analyze_target(target_url):
    target_url = target_url.rstrip('/')
    report = {
        "target": target_url,
        "robots_content": None,
        "paths_analyzed": []
    }

    print(f"\n{Fore.CYAN}[*] A iniciar análise automatizada para: {target_url}{Style.RESET_ALL}\n")

    # 1. Análise automática do /robots.txt
    robots_url = f"{target_url}/robots.txt"
    print(f"[*] A verificar o ficheiro robots.txt em {robots_url}...")
    try:
        resp = requests.get(robots_url, timeout=4)
        if resp.status_code == 200:
            print(f"{Fore.GREEN}[+] robots.txt encontrado e lido com sucesso!{Style.RESET_ALL}")
            report["robots_content"] = resp.text
            print(f"\n--- Conteúdo do robots.txt ---\n{resp.text}\n-----------------------------")
        else:
            print(f"{Fore.YELLOW}[-] robots.txt não encontrado ou inacessível (Código: {resp.status_code}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao aceder ao robots.txt: {e}{Style.RESET_ALL}")

    # 2. Inspeção de rotas comuns/descobertas (Redirecionamentos e Estados)
    paths_to_check = ["login", "dashboard", "index.php", "admin", "config.json"]
    print(f"\n[*] A inspecionar cabeçalhos das rotas principais...")

    for path in paths_to_check:
        url = f"{target_url}/{path}"
        try:
            # allow_redirects=False para capturar os códigos 301/302 e o destino (Location)
            response = requests.get(url, timeout=3, allow_redirects=False)
            status = response.status_code
            redirect_location = response.headers.get("Location", "N/A")

            path_data = {
                "path": path,
                "url": url,
                "status_code": status,
                "redirect_location": redirect_location
            }
            report["paths_analyzed"].append(path_data)

            if status == 200:
                print(f"  {Fore.GREEN}[200 OK]       -> {url}{Style.RESET_ALL}")
            elif status in [301, 302, 303, 307, 308]:
                print(f"  {Fore.YELLOW}[{status} REDIRECT] -> {url} (Aponta para: {redirect_location}){Style.RESET_ALL}")
            elif status == 403:
                print(f"  {Fore.BLUE}[403 FORBIDDEN]-> {url}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.MAGENTA}[{status}]           -> {url}{Style.RESET_ALL}")
        except requests.RequestException:
            pass

    # 3. Exportar relatório detalhado em JSON
    safe_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
    filename = f"analysis_report_{safe_name}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"\n{Fore.CYAN}[SALVO] Relatório analítico exportado com sucesso para: {filename}\n")

def main():
    parser = argparse.ArgumentParser(description="Script Automatizado de Análise e Reconhecimento Web")
    parser.add_argument("-url", required=True, help="URL alvo (ex: https://exemplo.com)")
    args = parser.parse_args()
    
    analyze_target(args.url)

if __name__ == "__main__":
    main()