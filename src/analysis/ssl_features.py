# ssl_features.py
import ssl
import socket
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def extract_ssl_features(url: str):
    ssl_features = {}
    ssl_success = True
    try:
        hostname = url.split("//")[-1].split("/")[0]
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
        conn.settimeout(5.0)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()

        # Use UTC versions to avoid deprecation
        not_before = cert.get('notBefore')  # fallback
        not_after = cert.get('notAfter')    # fallback
        try:
            not_before = cert.get('not_valid_before_utc', None) or not_before
            not_after = cert.get('not_valid_after_utc', None) or not_after
        except Exception:
            pass

        ssl_features["has_ssl"] = 1
        ssl_features["ssl_cert_expired"] = int(datetime.utcnow() > datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
        ssl_features["ssl_cert_self_signed"] = 0  # optional, implement if needed
        ssl_features["ssl_cert_valid_days"] = max(0, (datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z") - datetime.utcnow()).days)
    except Exception as e:
        logger.warning(f"SSL extraction failed for {url}: {e}")
        ssl_features = {
            "has_ssl": 0,
            "ssl_cert_expired": 1,
            "ssl_cert_self_signed": 0,
            "ssl_cert_valid_days": 0
        }
        ssl_success = False
    return ssl_features, ssl_success
