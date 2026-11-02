import hashlib
import json
import os
from colorama import Fore, Style, init

init(autoreset=True)

BASELINE_FILE = "fim_baseline.json"


def calculate_sha256(filepath):
    """Calcula o hash SHA-256 de um ficheiro lendo em blocos."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def scan_directory(directory):
    """Percorre a pasta especificada e gera um dicionário {caminho: hash}."""
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            # Ignora a própria base de dados do FIM para não gerar falsos alarmes
            if file == BASELINE_FILE:
                continue

            filepath = os.path.join(root, file)
            file_hash = calculate_sha256(filepath)
            if file_hash:
                file_hashes[filepath] = file_hash
    return file_hashes


def create_baseline(directory):
    """Gera o estado inicial (baseline) dos ficheiros e guarda em JSON."""
    print(
        f"\n{Fore.CYAN}[*] A gerar linha de base (baseline) para a pasta: {directory}{Style.RESET_ALL}"
    )
    hashes = scan_directory(directory)

    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=4)

    print(
        f"{Fore.GREEN}[+] Baseline guardada com sucesso em '{BASELINE_FILE}' ({len(hashes)} ficheiros monitorizados).{Style.RESET_ALL}"
    )


def check_integrity(directory):
    """Compara os hashes atuais com a baseline guardada."""
    if not os.path.exists(BASELINE_FILE):
        print(
            f"{Fore.RED}[ERRO] Nenhuma baseline encontrada em '{BASELINE_FILE}'. Crie uma primeiro (Opção 1).{Style.RESET_ALL}"
        )
        return

    print(
        f"\n{Fore.CYAN}[*] A verificar a integridade dos ficheiros em: {directory}{Style.RESET_ALL}\n"
    )

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline_hashes = json.load(f)

    current_hashes = scan_directory(directory)

    changes_detected = False

    # 1. Verificar ficheiros modificados ou removidos
    for filepath, original_hash in baseline_hashes.items():
        if filepath not in current_hashes:
            print(
                f"  {Fore.RED}[ALERTA - REMOVIDO]   -> {filepath}{Style.RESET_ALL}"
            )
            changes_detected = True
        elif current_hashes[filepath] != original_hash:
            print(
                f"  {Fore.RED}[ALERTA - MODIFICADO] -> {filepath}{Style.RESET_ALL}"
            )
            changes_detected = True
        else:
            print(
                f"  {Fore.GREEN}[INTACTO]             -> {filepath}{Style.RESET_ALL}"
            )

    # 2. Verificar novos ficheiros criados
    for filepath in current_hashes:
        if filepath not in baseline_hashes:
            print(
                f"  {Fore.YELLOW}[ALERTA - NOVO]       -> {filepath}{Style.RESET_ALL}"
            )
            changes_detected = True

    print("\n" + "=" * 60)
    if changes_detected:
        print(
            f"{Fore.RED}[!] ALERTA DE SEGURANÇA: Alterações de integridade detetadas!{Style.RESET_ALL}"
        )
    else:
        print(
            f"{Fore.GREEN}[+] SUCESSO: Todos os ficheiros coincidem com a linha de base.{Style.RESET_ALL}"
        )
    print("=" * 60)


def run_fim():
    print(
        f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════╗
║             FILE INTEGRITY MONITOR (FIM)             ║
║          Portfolio Security Script - Python          ║
╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    )

    directory = input(
        f"{Fore.YELLOW}[?] Caminho da pasta a monitorizar (ex: . ou C:\\pasta): {Style.RESET_ALL}"
    ).strip()

    if not directory or not os.path.exists(directory):
        print(
            f"{Fore.RED}[ERRO] Pasta inválida ou não encontrada.{Style.RESET_ALL}"
        )
        input("\nPressione ENTER para continuar...")
        return

    print("\nEscolha o modo de operação:")
    print("[1] Gerar/Atualizar Linha de Base (Nova Baseline)")
    print("[2] Verificar Integridade contra a Baseline Existente")

    opt = input(f"\n{Fore.GREEN}Opção desejada > {Style.RESET_ALL}").strip()

    if opt == "1":
        create_baseline(directory)
    elif opt == "2":
        check_integrity(directory)
    else:
        print(f"{Fore.RED}[ERRO] Opção inválida.{Style.RESET_ALL}")

    input(
        f"\n{Fore.DIM}Pressione ENTER para retornar ao menu principal...{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    run_fim()