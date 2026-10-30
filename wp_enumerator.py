import argparse
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def enumerate_wordpress(target_url):
    target_url = target_url.rstrip('/')
    
    print(f"\n{Fore.CYAN}[*] A iniciar enumeração WordPress para: {target_url}{Style.RESET_ALL}\n")

    # 1. Verificar o Sitemap
    sitemap_url = f"{target_url}/sitemap_index.xml"
    print(f"[*] A verificar sitemap em: {sitemap_url}")
    try:
        resp = requests.get(sitemap_url, timeout=4)
        if resp.status_code == 200:
            print(f"{Fore.GREEN}[+] Sitemap encontrado e acessível! ({sitemap_url}){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] Sitemap não encontrado diretamente (Código: {resp.status_code}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao aceder ao sitemap: {e}{Style.RESET_ALL}")

    # 2. Verificar Directory Indexing nos logs do WooCommerce (expostos no robots.txt)
    logs_url = f"{target_url}/wp-content/uploads/wc-logs/"
    print(f"\n[*] A verificar Directory Indexing em: {logs_url}")
    try:
        resp = requests.get(logs_url, timeout=4)
        if resp.status_code == 200:
            if "Index of" in resp.text:
                print(f"{Fore.RED}[ALERTA] Directory Indexing ATIVO! Ficheiros expostos em: {logs_url}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] Pasta existe (200 OK), mas a listagem de diretório parece estar desativada.{Style.RESET_ALL}")
        elif resp.status_code == 403:
            print(f"{Fore.GREEN}[+] Acesso negado (403 Forbidden) - Protegido corretamente.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] Código de resposta: {resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro ao testar logs: {e}{Style.RESET_ALL}")

    # 3. Enumeração de Plugins Comuns do WooCommerce/WordPress
    common_plugins = [
        "woocommerce",
        "wordpress-seo",
        "elementor",
        "contact-form-7",
        "wordfence"
    ]

    print(f"\n[*] A testar a existência de diretórios de plugins comuns...")
    for plugin in common_plugins:
        plugin_url = f"{target_url}/wp-content/plugins/{plugin}/"
        try:
            resp = requests.get(plugin_url, timeout=3)
            # Geralmente 403 ou 200 indicam que a pasta do plugin existe fisicamente
            if resp.status_code in [200, 403, 401]:
                print(f"  {Fore.GREEN}[DETECTADO] Plugin detetado/pasta existe -> {plugin} (Código: {resp.status_code}){Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}[-] Não detetado -> {plugin} (Código: {resp.status_code}){Style.RESET_ALL}")
        except requests.RequestException:
            pass

    print(f"\n{Fore.CYAN}[*] Enumeração WordPress concluída!{Style.RESET_ALL}\n")

def main():
    parser = argparse.ArgumentParser(description="Enumerador de Ambientes WordPress para Portfólio")
    parser.add_argument("-url", required=True, help="URL alvo (ex: https://exemplo.com)")
    args = parser.parse_args()
    
    enumerate_wordpress(args.url)

if __name__ == "__main__":
    main()