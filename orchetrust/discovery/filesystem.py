from pathlib import Path
from typing import Iterable, Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone

CERT_EXTS = {".pem", ".crt", ".cer"}

def _iter_candidate_files(paths: list[str]) -> Iterable[Path]:
    for base in paths:
        p = Path(base).expanduser()
        if p.is_file() and p.suffix.lower() in CERT_EXTS:
            yield p
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix.lower() in CERT_EXTS:
                    yield f

def _load_cert(path: Path) -> x509.Certificate | None:
    try:
        data = path.read_bytes()
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:
            return x509.load_der_x509_certificate(data)
    except Exception:
        return None

def _days_left(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    return int((dt - now).total_seconds() // 86400)

def _fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()

def scan_filesystem(paths: list[str]) -> list[Dict[str, Any]]:
    results = []
    for f in _iter_candidate_files(paths):
        cert = _load_cert(f)
        if not cert:
            continue
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        # Use *_utc to avoid deprecation warnings
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        days = _days_left(not_after)
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(x) for x in ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            sans = []
        results.append({
            "fingerprint": _fingerprint_sha256(cert),
            "source": "filesystem",
            "path": str(f),
            "subject": subject,
            "sans": sans,
            "issuer": issuer,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_left": days,
        })
    return results