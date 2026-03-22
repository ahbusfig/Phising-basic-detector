#!/usr/bin/env python3
"""
main.py — Punto de entrada del Phishing Detector CLI.
Por ahora solo analiza URLs.

Uso:
    python main.py
    python main.py -u "http://192.168.1.1/paypal/login"
    python main.py --batch urls.txt
"""

import sys
import argparse

from analyzer_url import analyze_url
from renderer     import render_result, render_batch_summary, render_banner


def run_interactive() -> None:
    render_banner()
    while True:
        try:
            entrada = input(">>> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSaliendo...")
            break

        if not entrada:
            continue
        if entrada.lower() in ("salir", "exit", "quit", "q"):
            print("Hasta luego.")
            break

        render_result(analyze_url(entrada))


def run_batch(filepath: str) -> None:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"Error: fichero '{filepath}' no encontrado.")
        sys.exit(1)

    print(f"\nProcesando {len(lines)} URL(s) desde '{filepath}'...\n")

    results = []
    for line in lines:
        result = analyze_url(line)
        render_result(result)
        results.append(result)

    render_batch_summary(results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing_detector",
        description="Detector de phishing — análisis heurístico de URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ejemplos:
  python main.py
  python main.py -u "http://192.168.1.1/paypal/login"
  python main.py --batch urls.txt
        """
    )
    parser.add_argument("-u", "--url",   help="URL a analizar")
    parser.add_argument("--batch",       help="Fichero .txt con una URL por línea")
    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.url:
        render_result(analyze_url(args.url))
    elif args.batch:
        run_batch(args.batch)
    else:
        run_interactive()


if __name__ == "__main__":
    main()