# 🎣 Phishing Detector CLI

Herramienta de línea de comandos para detectar URLs sospechosas mediante análisis heurístico. Sin dependencias externas, sin APIs, sin ML — solo reglas bien definidas y scoring por pesos.

## ¿Cómo funciona?

Cada URL analizada pasa por 9 checks independientes. Cada check tiene un peso asignado según su relevancia como indicador de phishing. La suma de los pesos activados produce un score final que clasifica la URL en tres niveles:

| Score | Nivel |
|-------|-------|
| 0 – 20 | ✔ Bajo riesgo |
| 21 – 50 | ⚠ Sospechoso |
| 51+ | ✘ Alto riesgo de phishing |

## Checks implementados

| Check | Peso | Descripción |
|-------|------|-------------|
| Sin HTTPS | 15 | El esquema no es HTTPS |
| IP en URL | 30 | El host es una IP directa en lugar de un dominio |
| Subdominios excesivos | 20 | Más de 2 niveles de subdominio |
| TLD sospechoso | 25 | Extensiones gratuitas o baratas asociadas a phishing |
| Palabras clave sensibles | 15 | `login`, `verify`, `secure`, `account`... |
| URL excesivamente larga | 10 | Más de 75 caracteres |
| Carácter @ en URL | 25 | Técnica para redirigir a otro host |
| Typosquatting | 30 | Nombre de marca conocida en dominio no oficial |
| Guiones excesivos | 15 | 3 o más guiones en el subdominio principal |

## Uso
```bash
# Modo interactivo
python main.py

# URL directa
python main.py -u "http://192.168.1.1/paypal/login"

# Fichero con varias URLs (una por línea, # para comentarios)
python main.py --batch urls.txt
```

## Ejemplo de salida
```
────────────────────────────────────────────────────────────
  Analizando: http://secure-login-santander-verify.tk/acceso
────────────────────────────────────────────────────────────

  Score: 100  [████████████████████████████████████████]
  ✘  ALTO RIESGO DE PHISHING

  Flags activadas (5):
    ✘  Sin HTTPS
       Usa HTTP en lugar de HTTPS
    ✘  TLD sospechoso
       Extensión .tk frecuente en phishing (gratuita o barata)
    ✘  Palabras clave sensibles
       Detectado: "login"
    ✘  Typosquatting / suplantación de marca
       "santander" en dominio no oficial
    ✘  Guiones excesivos en dominio
       3 guión(es) en el subdominio principal

  Checks limpios (4):
    ✔  IP en URL
    ✔  Subdominios excesivos
    ✔  URL excesivamente larga
    ✔  Carácter @ en URL
────────────────────────────────────────────────────────────
```

## Requisitos

Python 3.8 o superior. Sin dependencias externas.

## Limitaciones conocidas

- Los checks son heurísticos — puede haber falsos positivos en dominios legítimos con palabras clave comunes como `login` o `secure`.
- El typosquatting por homoglyphs (`paypa1.com`) no se detecta con este enfoque — requeriría distancia de Levenshtein.
- No consulta listas negras externas ni APIs de threat intelligence.

## Posibles mejoras

- Integración con la API de VirusTotal para contrastar contra 70+ motores
- WHOIS lookup para detectar dominios recién registrados (< 30 días)
- Distancia de Levenshtein para homoglyphs y typosquatting avanzado
- Exportación de resultados a JSON para integración con SIEMs
