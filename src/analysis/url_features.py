import urllib.parse
import re
from fuzzywuzzy import fuzz

def extract_url_features(url):
    """Extract combined URL features (structural + advanced)"""

    # Parse URL
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = {
        # --- Basic structural features ---
        'url_length': len(url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query),
        'fd_length': fd_length(url),   # First directory length

        # --- Counts of symbols ---
        'count_dot': url.count('.'),
        'count_hyphen': url.count('-'),
        'count_at': url.count('@'),
        'count_question_mark': url.count('?'),
        'count_equal': url.count('='),
        'count_percent': url.count('%'),
        'count_slash': url.count('/'),
        'count_www': count_www(url),
        'count_https': count_https(url),
        'count_http': count_http(url),

        # --- Extra lexical features ---
        'domain_length': len(hostname),
        'has_ip': 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) else 0,
        'letter_count': sum(c.isalpha() for c in url),
        'digit_count': sum(c.isdigit() for c in url),
        'num_other_special_chars': sum(c == '%' for c in url),
        'tld_length': len(url.split('.')[-1]) if '.' in url else 0,
        'is_shortened': 1 if any(short in url for short in ['bit.ly', 't.co']) else 0,
        'num_obfuscated_chars': url.count('%'),

        # --- Ratios ---
        'letter_ratio': (sum(c.isalpha() for c in url) / len(url)) if len(url) > 0 else 0,
        'obfuscation_ratio': 0,          # Placeholder
        'char_continuation_rate': 0,     # Placeholder
        'tld_legitimate_prob': 0,        # Placeholder
        'url_char_prob': 0,              # Placeholder

        # --- Similarity to popular domains ---
        'url_similarity_index': max(fuzz.ratio(url, d) for d in ['example.com', 'google.com']) / 100.0,
    }

    return features


# --- Helper functions ---
def count_www(url):
    return url.lower().count('www')

def count_https(url):
    return len(re.findall(r'https', url.lower()))

def count_http(url):
    all_http = url.lower().count('http')
    https_count = count_https(url)
    return max(0, all_http - https_count)

def fd_length(url):
    try:
        path = urllib.parse.urlparse(url).path
        directories = path.split('/')
        if len(directories) > 1 and directories[1]:
            return len(directories[1])
        else:
            return 0
    except:
        return 0
