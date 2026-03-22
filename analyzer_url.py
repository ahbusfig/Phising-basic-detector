"""
analyzer_url.py — Análisis heurístico de URLs sospechosas.
Devuelve un dict con flags individuales y score total.
"""
import re
from urllib.parse import urlparse
from rules import SUSPICIOUS_TLDS, SUSPICIOUS_KEYWORDS, BRAND_NAMES

def analyze_url(url: str) -> dict:
    """
    Analiza una URL y devuelve flags de riesgo con su score.

    Returns:
        dict con claves: type, input, hostname, flags, score
        o dict con clave 'error' si la URL no es válida
    """
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        return {"error": "URL inválida: debe comenzar por http:// o https://"}

    try:
        parsed = urlparse(raw)
        hostname = parsed.netloc.lower().split(":")[0]
    except Exception:
        return {"error": "URL no válida"}

    if not hostname:
        return {"error": "No se pudo extraer el hostname"}

    flags = []

    flags.append(_check_https(parsed))
    flags.append(_check_ip(hostname))
    flags.append(_check_subdomains(hostname))
    flags.append(_check_tld(hostname))
    flags.append(_check_keywords(parsed, hostname))
    flags.append(_check_length(url))
    flags.append(_check_at_sign(parsed))
    flags.append(_check_typosquatting(hostname))
    flags.append(_check_dashes(hostname))

    score = sum(f["weight"] for f in flags if f["triggered"])
    return {
        "type": "url",
        "input": url,
        "hostname": hostname,
        "flags": flags,
        "score": score
    }

# ── Checks individuales ────────────────────────────────────────

def _check_https(parsed) -> dict:
    return {
        "id": "https",
        "name": "Sin HTTPS",
        "desc": f"Usa {parsed.scheme.upper()} en lugar de HTTPS",
        "triggered": parsed.scheme != "https",
        "weight": 15
    }

def _check_ip(hostname: str) -> dict:
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    triggered = bool(ip_pattern.match(hostname))
    return {
        "id": "ip_url",
        "name": "IP en URL",
        "desc": f"El host es una IP directa: {hostname}",
        "triggered": triggered,
        "weight": 30
    }

def _check_subdomains(hostname: str) -> dict:
    subdomains = len(hostname.split(".")) - 2
    return {
        "id": "subdomains",
        "name": "Subdominios excesivos",
        "desc": f"{subdomains} nivel(es) de subdominio — técnica para ocultar dominio real",
        "triggered": subdomains > 2,
        "weight": 20
    }

def _check_tld(hostname: str) -> dict:
    tld = hostname.split(".")[-1]
    return {
        "id": "tld",
        "name": "TLD sospechoso",
        "desc": f"Extensión .{tld} frecuente en phishing (gratuita o barata)",
        "triggered": tld in SUSPICIOUS_TLDS,
        "weight": 25
    }

def _check_keywords(parsed, hostname: str) -> dict:
    full_path = (parsed.path + parsed.query).lower()
    found = next((k for k in SUSPICIOUS_KEYWORDS if k in full_path or k in hostname), None)
    return {
        "id": "keywords",
        "name": "Palabras clave sensibles",
        "desc": f'Detectado: "{found}"' if found else "Sin palabras clave sospechosas",
        "triggered": found is not None,
        "weight": 15
    }

def _check_length(url: str) -> dict:
    return {
        "id": "length",
        "name": "URL excesivamente larga",
        "desc": f"{len(url)} caracteres (umbral: 75)",
        "triggered": len(url) > 75,
        "weight": 10
    }

def _check_at_sign(parsed) -> dict:
    return {
        "id": "at_sign",
        "name": "Carácter @ en URL",
        "desc": "Puede usarse para redirigir: http://legit.com@evil.com",
        "triggered": "@" in parsed.netloc,
        "weight": 25
    }

def _check_typosquatting(hostname: str) -> dict:
    brand_match = next(
        (b for b in BRAND_NAMES
         if b in hostname
         and not hostname.endswith(f"{b}.com")
         and not hostname.endswith(f"{b}.es")),
        None
    )
    return {
        "id": "typosquat",
        "name": "Typosquatting / suplantación de marca",
        "desc": f'"{brand_match}" en dominio no oficial' if brand_match else "Sin suplantación de marca",
        "triggered": brand_match is not None,
        "weight": 30
    }

def _check_dashes(hostname: str) -> dict:

    dash_count = hostname.split(".")[0].count("-")
    return {
        "id": "dashes",
        "name": "Guiones excesivos en dominio",
        "desc": f"{dash_count} guión(es) en el subdominio principal",
        "triggered": dash_count >= 3,
        "weight": 15
    }


if __name__ == "__main__":
    test_cases = [
        ("IP directa",           "http://192.168.1.1/paypal/login",                   ["ip_url", "https", "keywords"]),
        ("Subdominios excesivos","https://paypal.com.login.secure.verify.evil.xyz",   ["subdomains", "tld", "keywords", "typosquat"]),
        ("Typosquatting",        "https://paypa1-login-secure-verify.com/account",    ["keywords", "dashes"]),
        ("Arroba en URL",        "http://legit.com@evil.com/login",                   ["https", "at_sign", "keywords"]),
        ("URL limpia",           "https://google.com",                                []),
        ("URL muy larga",        "https://normal.com/" + "a" * 80,                   ["length"]),
        ("Sin esquema",          "paypal.com/login",                                  None),
        ("Cadena vacía",         "",                                                  None),
    ]

    passed = 0
    failed = 0

    print("\n── Tests: analyzer_url.py ──\n")

    for desc, url, expected_triggered in test_cases:
        result = analyze_url(url)
        error_returned = "error" in result

        if expected_triggered is None:
            ok = error_returned
            icon = "✔" if ok else "✘"
            print(f"  {icon}  [ERROR ESPERADO]           {desc}")
            if not ok:
                print(f"           Se analizó sin error — score {result['score']}")
        else:
            if error_returned:
                print(f"  ✘  [ERROR INESPERADO]          {desc}")
                print(f"           → {result['error']}")
                failed += 1
                continue

            verdict = (
                "BAJO RIESGO            " if result["score"] <= 20 else
                "SOSPECHOSO             " if result["score"] <= 50 else
                "ALTO RIESGO DE PHISHING"
            )

            actual_triggered = {f["id"] for f in result["flags"] if f["triggered"]}
            missing    = set(expected_triggered) - actual_triggered
            unexpected = actual_triggered - set(expected_triggered)
            ok = not missing and not unexpected

            icon = "✔" if ok else "✘"
            print(f"  {icon}  [{result['score']:>3}pts]  {verdict}  {desc}")
            if missing:
                print(f"           Faltaban activarse: {missing}")
            if unexpected:
                print(f"           Activadas de más:   {unexpected}")

        passed += 1 if ok else 0
        failed += 0 if ok else 1

    print(f"\n  {passed} passed · {failed} failed\n")

