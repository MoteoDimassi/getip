"""Разбор адресов сайтов и доменных имён."""
import re

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")

# системные домены macOS, которые светятся в любом трафике — их не показываем
NOISE_DOMAINS = {"apple.com", "icloud.com", "apple-dns.net", "aaplimg.com", "mzstatic.com",
                 "apple.news", "cdn-apple.com", "icloud-content.com", "apple-cloudkit.com",
                 "itunes.com", "push.apple.com"}


def normalize_domain(text):
    s = (text or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.split(r"[/?#]", s)[0].split("@")[-1].split(":")[0].strip(".")
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode()
    except UnicodeError:
        return None
    return s if DOMAIN_RE.match(s) else None


def matches(name, domain):
    name = name.rstrip(".").lower()
    return name == domain or name.endswith("." + domain)


def base_domain(name):
    """Домен второго уровня: cdn.x.example.com → example.com, a.b.co.uk → b.co.uk."""
    parts = name.split(".")
    n = 3 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in (
        "co", "com", "net", "org", "gov", "edu", "ac") else 2
    return ".".join(parts[-n:])


def is_noise(name):
    return name.endswith((".arpa", ".local")) or base_domain(name) in NOISE_DOMAINS
