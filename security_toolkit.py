import subprocess
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║               PYTHON SECURITY TOOLKIT                ║
║         Suite de Ferramentas de Cibersegurança       ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """)

def run_command(command_list):
    """Executa uma lista de comandos no terminal."""
    print(f"\n{Fore.YELLOW}[*] A executar comando...{Style.RESET_ALL}\n")
    try:
        subprocess.run(command_list)
    except Exception as e:
        print(f"{Fore.RED}[ERRO] Ocorreu um erro ao executar: {e}{Style.RESET_ALL}")
    
    input(f"\n{Fore.CYAN}Pressiona ENTER para voltar ao menu principal...{Style.RESET_ALL}")

def main():
    while True:
        banner()
        print(f"{Fore.GREEN}Escolhe uma ferramenta para executar:{Style.RESET_ALL}")
        print("  [1] OSINT Recon Analyzer (Reconhecimento de Domínios/APIs)")
        print("  [2] TCP Port Scanner (Varredura de Portas Multithreaded)")
        print("  [3] Web Directory Fuzzer (Descoberta de Diretórios Web)")
        print("  [4] WordPress Enumerator (Análise e Enumeração CMS WP)")
        print("  [0] Sair do Toolkit\n")

        choice = input(f"{Fore.YELLOW}Opção desejada > {Style.RESET_ALL}").strip()

        if choice == "1":
            domain = input(f"{Fore.CYAN}Digite o domínio alvo (ex: exemplo.com) > {Style.RESET_ALL}").strip()
            if domain:
                run_command([sys.executable, "osint_analyzer.py", "-domain", domain])

        elif choice == "2":
            ip = input(f"{Fore.CYAN}Digite o IP ou domínio alvo (ex: 127.0.0.1) > {Style.RESET_ALL}").strip()
            start = input(f"{Fore.CYAN}Porta inicial [Padrão: 1] > {Style.RESET_ALL}").strip() or "1"
            end = input(f"{Fore.CYAN}Porta final [Padrão: 1024] > {Style.RESET_ALL}").strip() or "1024"
            if ip:
                run_command([sys.executable, "port_scanner.py", "-ip", ip, "-start", start, "-end", end])

        elif choice == "3":
            url = input(f"{Fore.CYAN}Digite o URL alvo (ex: http://exemplo.com) > {Style.RESET_ALL}").strip()
            wordlist = input(f"{Fore.CYAN}Digite o caminho da wordlist (ex: wordlist.txt) > {Style.RESET_ALL}").strip()
            if url and wordlist:
                run_command([sys.executable, "web_fuzzer.py", "-url", url, "-wordlist", wordlist])

        elif choice == "4":
            url = input(f"{Fore.CYAN}Digite o URL do site WordPress (ex: https://exemplo.com) > {Style.RESET_ALL}").strip()
            if url:
                run_command([sys.executable, "wp_enumerator.py", "-url", url])

        elif choice == "0":
            print(f"\n{Fore.CYAN}[*] A sair do Security Toolkit. Até logo!{Style.RESET_ALL}\n")
            break
        else:
            print(f"\n{Fore.RED}[!] Opção inválida. Tenta novamente.{Style.RESET_ALL}")
            input(f"Pressiona ENTER para continuar...")

if __name__ == "__main__":
    main()