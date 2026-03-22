"""
renderer.py — Renderizado de resultados en terminal.
Usa códigos ANSI directamente, sin dependencias externas.
"""

import os
import sys

if sys.platform == "win32":
    os.system("")

class Fore:
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    GREEN  = "\033[32m"
    CYAN   = "\033[36m"

class Style:
    BRIGHT    = "\033[1m"
    DIM       = "\033[2m"
    RESET_ALL = "\033[0m"

from rules import SCORE_LOW, SCORE_MEDIUM

BAR_LEN = 40


def get_verdict(score: int) -> tuple:
    """Devuelve (texto, color, icono) según el score."""
    if score <= SCORE_LOW:
        return "BAJO RIESGO",             Fore.GREEN,  "✔"
    elif score <= SCORE_MEDIUM:
        return "SOSPECHOSO",              Fore.YELLOW, "⚠"
    else:
        return "ALTO RIESGO DE PHISHING", Fore.RED,    "✘"


def render_result(result: dict) -> None:
    """Imprime el resultado completo de un análisis."""
    if "error" in result:
        print(f"\n{Fore.RED}Error: {result['error']}{Style.RESET_ALL}")
        return

    score     = result["score"]
    flags     = result["flags"]
    triggered = [f for f in flags if f["triggered"]]
    clean     = [f for f in flags if not f["triggered"]]
    verdict_text, verdict_color, verdict_icon = get_verdict(score)

    _print_header(result["input"])
    _print_score(score, verdict_text, verdict_color, verdict_icon)
    _print_triggered(triggered)
    _print_clean(clean)
    print(f"{'─' * 60}\n")


def render_batch_summary(results: list) -> None:
    """Imprime el resumen al final de un análisis batch."""
    high   = sum(1 for r in results if r.get("score", 0) > SCORE_MEDIUM)
    medium = sum(1 for r in results if SCORE_LOW < r.get("score", 0) <= SCORE_MEDIUM)
    low    = sum(1 for r in results if r.get("score", 0) <= SCORE_LOW)

    print(f"{Style.BRIGHT}── Resumen batch ──{Style.RESET_ALL}")
    print(f"  {Fore.RED}Alto riesgo:  {high}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Sospechoso:   {medium}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Bajo riesgo:  {low}{Style.RESET_ALL}\n")


def render_banner() -> None:
    """Imprime el banner de inicio del modo interactivo."""
    print(f"\n{Style.BRIGHT}╔══════════════════════════════════════╗")
    print(f"║     PHISHING DETECTOR  v2.0          ║")
    print(f"║  Escribe 'salir' para terminar       ║")
    print(f"╚══════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"  Modo: {Fore.CYAN}interactivo{Style.RESET_ALL} — introduce URLs\n")


# ── Helpers privados ───────────────────────────────────────────

def _print_header(input_str: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {Style.BRIGHT}Analizando:{Style.RESET_ALL} {input_str}")
    print(f"{'─' * 60}")


def _print_score(score: int, verdict_text: str, verdict_color: str, verdict_icon: str) -> None:
    filled = int((min(score, 100) / 100) * BAR_LEN)
    bar    = "█" * filled + "░" * (BAR_LEN - filled)
    print(f"\n  {Style.BRIGHT}Score:{Style.RESET_ALL} {verdict_color}{Style.BRIGHT}{score:>3}{Style.RESET_ALL}  "
          f"{verdict_color}[{bar}]{Style.RESET_ALL}")
    print(f"  {verdict_color}{Style.BRIGHT}{verdict_icon}  {verdict_text}{Style.RESET_ALL}\n")


def _print_triggered(triggered: list) -> None:
    if not triggered:
        print(f"  {Fore.GREEN}Sin flags activadas.{Style.RESET_ALL}")
        return
    print(f"  {Style.BRIGHT}Flags activadas ({len(triggered)}):{Style.RESET_ALL}")
    for f in triggered:
        print(f"    {Fore.RED}✘{Style.RESET_ALL}  {Style.BRIGHT}{f['name']}{Style.RESET_ALL}")
        print(f"       {Style.DIM}{f['desc']}{Style.RESET_ALL}")


def _print_clean(clean: list) -> None:
    if not clean:
        return
    print(f"\n  {Style.BRIGHT}Checks limpios ({len(clean)}):{Style.RESET_ALL}")
    for f in clean:
        print(f"    {Fore.GREEN}✔{Style.RESET_ALL}  {Style.DIM}{f['name']}{Style.RESET_ALL}")