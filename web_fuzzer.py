import argparse
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description="Web Directory Fuzzer para Portfólio de Cibersegurança")
    parser.add_argument("-url", required=True, help="URL alvo (ex: http://exemplo.com)")
    parser.add_argument("-wordlist", required=True, help="Caminho para o ficheiro de wordlist (ex: wordlist.txt)")

    args = parser.parse_args()
    target_url = args.url.rstrip('/')
    wordlist_path = args.wordlist

    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║                WEB DIRECTORY FUZZER                  ║
║          Portfolio Security Script - Python          ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """)

    print(f"[*] Alvo definido: {target_url}")
    print(f"[*] A carregar wordlist: {wordlist_path}\n" + "="*50)

    try:
        with open(wordlist_path, "r", encoding="utf-8") as file:
            words = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[ERRO]{Style.RESET_ALL} O ficheiro de wordlist '{wordlist_path}' não foi encontrado.")
        return

    print(f"[*] Total de palavras carregadas: {len(words)}")
    print(f"[*] Iniciando varredura...\n" + "="*50)

    for word in words:
        if not word or word.startswith('#'):
            continue
        
        url_to_test = f"{target_url}/{word}"
        try:
            # Faz a requisição HTTP sem seguir redirecionamentos automáticos
            response = requests.get(url_to_test, timeout=2.5, allow_redirects=False)
            status = response.status_code

            # Classifica o resultado pelo código HTTP
            if status == 200:
                print(f"{Fore.GREEN}[200 OK]       -> {url_to_test}{Style.RESET_ALL}")
            elif status in [301, 302, 303, 307, 308]:
                print(f"{Fore.YELLOW}[{status} REDIRECT] -> {url_to_test}{Style.RESET_ALL}")
            elif status == 403:
                print(f"{Fore.BLUE}[403 FORBIDDEN]-> {url_to_test}{Style.RESET_ALL}")
        except requests.RequestException:
            # Ignora erros de conexão para o script não parar se o servidor falhar num pedido
            pass

    print("=" * 50)
    print(f"{Fore.CYAN}[*] Fuzzing concluído!{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()