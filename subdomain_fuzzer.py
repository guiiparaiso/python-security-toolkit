import socket
import sys
from colorama import Fore, Style, init

init(autoreset=True)


def run_subdomain_fuzzer():
    print(
        f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║               SUBDOMAIN BRUTE-FORCER                 ║
║          Portfolio Security Script - Python          ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    )

    domain = (
        input(
            f"{Fore.YELLOW}[?] Digite o domínio alvo (ex: exemplo.com): {Style.RESET_ALL}"
        )
        .strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )

    wordlist_path = input(
        f"{Fore.YELLOW}[?] Caminho da wordlist de subdomínios (ex: subdomains.txt): {Style.RESET_ALL}"
    ).strip()

    if not domain or not wordlist_path:
        print(f"{Fore.RED}[ERRO] Entradas inválidas fornecidas.{Style.RESET_ALL}")
        input("\nPressione ENTER para continuar...")
        return

    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(
            f"{Fore.RED}[ERRO] Ficheiro '{wordlist_path}' não encontrado.{Style.RESET_ALL}"
        )
        input("\nPressione ENTER para continuar...")
        return

    print(f"\n{Fore.CYAN}[*] A iniciar varredura em {domain}...{Style.RESET_ALL}")
    print(f"[*] Total de prefixos a testar: {len(subdomains)}\n" + "=" * 50)

    found_count = 0
    for sub in subdomains:
        target_host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target_host)
            print(
                f"{Fore.GREEN}[DESCOBERTO]{Style.RESET_ALL} {target_host:<30} -> {ip}"
            )
            found_count += 1
        except socket.gaierror:
            pass

    print("=" * 50)
    print(
        f"{Fore.BLUE}[INFO]{Style.RESET_ALL} Varredura concluída. {found_count} subdomínio(s) encontrado(s)."
    )
    input(
        f"\n{Fore.DIM}Pressione ENTER para retornar ao menu principal...{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    run_subdomain_fuzzer()