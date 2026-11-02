import math
import re
from colorama import Fore, Style, init

init(autoreset=True)


def calculate_entropy(password):
    """Calcula a entropia da palavra-passe em bits."""
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32

    if pool_size == 0 or len(password) == 0:
        return 0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def analyze_password(password):
    """Avalia os critérios e a segurança geral da palavra-passe."""
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    entropy = calculate_entropy(password)

    print(
        f"\n{Fore.CYAN}=== Resultado da Análise de Palavra-Passe ==={Style.RESET_ALL}"
    )
    print(f"Comprimento: {length} caracteres")
    print(
        f"Letras Minúsculas: {'✓' if has_lower else '✗'} | Letras Maiúsculas: {'✓' if has_upper else '✗'}"
    )
    print(
        f"Números: {'✓' if has_digit else '✗'} | Caracteres Especiais: {'✓' if has_special else '✗'}"
    )
    print(f"Entropia Estimada: {entropy} bits")

    if entropy < 40:
        strength = f"{Fore.RED}MUITO FRACA{Style.RESET_ALL}"
    elif entropy < 60:
        strength = f"{Fore.YELLOW}MÉDIA{Style.RESET_ALL}"
    elif entropy < 80:
        strength = f"{Fore.GREEN}FORTE{Style.RESET_ALL}"
    else:
        strength = f"{Fore.GREEN}{Style.BRIGHT}MUITO FORTE / EXCELENTE{Style.RESET_ALL}"

    print(f"Nível de Segurança: {strength}\n")


def run_password_analyzer():
    print(
        f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║            PASSWORD STRENGTH & ENTROPY CHECKER       ║
║          Portfolio Security Script - Python          ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    )

    pwd = input(
        f"{Fore.YELLOW}[?] Digite a palavra-passe a analisar: {Style.RESET_ALL}"
    ).strip()
    if pwd:
        analyze_password(pwd)
    else:
        print(f"{Fore.RED}[ERRO] Nenhuma palavra-passe introduzida.{Style.RESET_ALL}")

    input(
        f"\n{Fore.DIM}Pressione ENTER para retornar ao menu principal...{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    run_password_analyzer()