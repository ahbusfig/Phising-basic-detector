"""
rules.py — Datos de referencia para el detector de phishing.
Centraliza TLDs, keywords y marcas para facilitar mantenimiento.
"""

SUSPICIOUS_TLDS = {
    "xyz", "tk", "top", "ml", "gq", "ga", "cf", "pw",
    "click", "work", "link", "loan", "download", "win",
    "stream", "online", "site", "website", "tech"
}

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "update", "bank",
    "signin", "confirm", "password", "credential", "suspended",
    "urgent", "immediately", "validate", "recover", "security-alert"
]

BRAND_NAMES = [
    "paypal", "amazon", "apple", "microsoft", "netflix",
    "google", "facebook", "ebay", "bankia", "santander",
    "bbva", "caixabank", "instagram", "whatsapp", "correos"
]

# Dominios oficiales conocidos — excluidos del check de typosquatting
OFFICIAL_DOMAINS = {
    "paypal.com", "paypal.es",
    "amazon.com", "amazon.es",
    "apple.com",
    "microsoft.com",
    "netflix.com",
    "google.com", "google.es",
    "facebook.com",
    "ebay.com", "ebay.es",
    "santander.com", "santander.es",
    "bbva.com", "bbva.es",
    "caixabank.com", "caixabank.es",
}

# Umbrales de scoring
SCORE_LOW      = 20   # <= LOW  → bajo riesgo
SCORE_MEDIUM   = 50   # <= MED  → sospechoso
                      # >  MED  → alto riesgo

URGENCY_WORDS = [
    "urgente", "urgent", "verify", "confirma",
    "suspended", "immediately", "alert", "security"
]