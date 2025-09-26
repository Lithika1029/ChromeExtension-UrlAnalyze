# combine_all_features.py - ROBUST VERSION
import sys
import os
import re
from urllib.parse import urlparse
import logging

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from analysis.url_features import extract_url_features
from analysis.header_features import extract_header_features
from analysis.dns_features import extract_dns_features_advanced
from analysis.ssl_features import extract_ssl_features
from analysis.meta_features import extract_metadata_features

logger = logging.getLogger(__name__)

# ---------------- Helper functions ----------------

def count_https(url):
    try:
        return len(re.findall(r'https', url.lower()))
    except:
        return 0

def count_http(url):
    try:
        all_http = url.lower().count('http')
        https_count = count_https(url)
        return max(0, all_http - https_count)
    except:
        return 0

def fd_length(url):
    try:
        path = urlparse(url).path
        directories = path.split('/')
        for directory in directories:
            if directory:
                return len(directory)
        return 0
    except:
        return 0

def count_embed_domain(url):
    try:
        netloc = urlparse(url).netloc
        if netloc.count('.') > 1:
            return netloc.count('.') - 1
        return 0
    except:
        return 0

def safe_get(feature_dict, key):
    """Return feature value or 0 if missing/None"""
    return feature_dict.get(key) if feature_dict.get(key) is not None else 0

# ---------------- Main function ----------------

def combine_all_features(url, use_faux_headers=True):
    """
    Extracts and combines features from URL, headers, DNS, SSL, and metadata.
    Returns both a feature_vector (list) and feature_dict (dict).
    """
    feature_dict = {}
    feature_vector = []

    try:
        # --- Extract from each module ---
        url_features = extract_url_features(url)   # ✅ Updated with new features
        header_features = extract_header_features(url, use_faux=use_faux_headers)
        dns_features = extract_dns_features_advanced(url)
        ssl_features = extract_ssl_features(url)
        metadata_features = extract_metadata_features(url)

        # --- Build feature_dict ---
        feature_dict = {
            # URL Features (Updated)
            "url_length": safe_get(url_features, 'url_length'),
            "hostname_length": safe_get(url_features, 'hostname_length'),
            "path_length": safe_get(url_features, 'path_length'),
            "query_length": safe_get(url_features, 'query_length'),
            "fd_length": safe_get(url_features, 'fd_length'),
            "count_dot": safe_get(url_features, 'count_dot'),
            "count_hyphen": safe_get(url_features, 'count_hyphen'),
            "count_at": safe_get(url_features, 'count_at'),
            "count_question_mark": safe_get(url_features, 'count_question_mark'),
            "count_equal": safe_get(url_features, 'count_equal'),
            "count_percent": safe_get(url_features, 'count_percent'),
            "count_slash": safe_get(url_features, 'count_slash'),
            "count_www": safe_get(url_features, 'count_www'),
            "count_https": safe_get(url_features, 'count_https'),
            "count_http": safe_get(url_features, 'count_http'),

            # Extra lexical + heuristic URL features
            "domain_length": safe_get(url_features, 'domain_length'),
            "has_ip": safe_get(url_features, 'has_ip'),
            "letter_count": safe_get(url_features, 'letter_count'),
            "digit_count": safe_get(url_features, 'digit_count'),
            "num_other_special_chars": safe_get(url_features, 'num_other_special_chars'),
            "tld_length": safe_get(url_features, 'tld_length'),
            "is_shortened": safe_get(url_features, 'is_shortened'),
            "num_obfuscated_chars": safe_get(url_features, 'num_obfuscated_chars'),
            "letter_ratio": safe_get(url_features, 'letter_ratio'),
            "url_similarity_index": safe_get(url_features, 'url_similarity_index'),
            "embed_domain_count": count_embed_domain(url),

            # Header Features
            "has_x_powered_by": safe_get(header_features, 'has_x_powered_by'),
            "has_server_header": safe_get(header_features, 'has_server_header'),
            "has_x_frame_options": safe_get(header_features, 'has_x_frame_options'),
            "has_strict_transport_security": safe_get(header_features, 'has_strict_transport_security'),
            "has_content_security_policy": safe_get(header_features, 'has_content_security_policy'),
            "has_x_content_type_options": safe_get(header_features, 'has_x_content_type_options'),
            "content_type_length": safe_get(header_features, 'content_type_length'),
            "server_length": safe_get(header_features, 'server_length'),

            # DNS Features
            "dns_record_count": safe_get(dns_features, 'dns_record_count'),
            "has_dns_record": safe_get(dns_features, 'has_dns_record'),
            "ip_reputation": safe_get(dns_features, 'ip_reputation'),
            "dns_response_time": safe_get(dns_features, 'dns_response_time'),
            "has_multiple_ips": safe_get(dns_features, 'has_multiple_ips'),
            "ttl_value": safe_get(dns_features, 'ttl_value'),

            # SSL Features
            "has_ssl": safe_get(ssl_features, 'has_ssl'),
            "ssl_cert_valid_days": safe_get(ssl_features, 'ssl_cert_valid_days'),
            "ssl_cert_expired": safe_get(ssl_features, 'ssl_cert_expired'),
            "ssl_cert_self_signed": safe_get(ssl_features, 'ssl_cert_self_signed'),
            "ssl_cert_chain_length": safe_get(ssl_features, 'ssl_cert_chain_length'),
            "ssl_cert_key_length": safe_get(ssl_features, 'ssl_cert_key_length'),

            # Metadata Features
            "domain_age_days": safe_get(metadata_features, 'domain_age_days'),
            "has_whois_info": safe_get(metadata_features, 'has_whois_info'),
            "is_domain_registered": safe_get(metadata_features, 'is_domain_registered'),
            "registrar_length": safe_get(metadata_features, 'registrar_length'),
            "has_privacy_protection": safe_get(metadata_features, 'has_privacy_protection'),
            "name_server_count": safe_get(metadata_features, 'name_server_count'),
        }

        # --- Build feature_vector (ordered list) ---
        feature_vector = [feature_dict[key] for key in feature_dict]

    except Exception as e:
        logger.error(f"Error combining features for {url}: {e}")

    return feature_vector, feature_dict
