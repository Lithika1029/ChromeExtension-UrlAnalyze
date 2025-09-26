import whois
from datetime import datetime
import urllib.parse
import tldextract

def extract_metadata_features(url):
    """Extract WHOIS and domain metadata features"""
    features = {
        'domain_age_days': 0,
        'has_whois_info': 0,
        'is_domain_registered': 0,
        'registrar_length': 0,
        'has_privacy_protection': 0,
        'name_server_count': 0,
    }
    
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        ext = tldextract.extract(domain)
        main_domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain
        
        if ':' in main_domain:
            main_domain = main_domain.split(':')[0]
        
        if main_domain in ['localhost', '127.0.0.1', '::1'] or main_domain.replace('.', '').isdigit():
            return features
        
        w = whois.whois(main_domain)
        
        if w:
            domain_age = 0
            creation_date = None
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if isinstance(creation_date, str):
                    try:
                        creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        try:
                            creation_date = datetime.strptime(creation_date, '%d-%b-%Y')
                        except ValueError:
                            creation_date = None
            
            if creation_date and isinstance(creation_date, datetime):
                domain_age = (datetime.now() - creation_date).days
            
            name_server_count = 0
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    name_server_count = len(w.name_servers)
                elif isinstance(w.name_servers, str):
                    name_server_count = 1
            
            registrar_length = 0
            if w.registrar:
                if isinstance(w.registrar, list):
                    registrar_length = len(w.registrar[0]) if w.registrar else 0
                elif isinstance(w.registrar, str):
                    registrar_length = len(w.registrar)
            
            has_privacy = 0
            if w.registrar:
                registrar_str = w.registrar[0] if isinstance(w.registrar, list) else str(w.registrar)
                privacy_indicators = ['privacy', 'protect', 'whois', 'mask', 'anonymous']
                if any(indicator in registrar_str.lower() for indicator in privacy_indicators):
                    has_privacy = 1
            
            if hasattr(w, 'org') and w.org:
                org_str = w.org[0] if isinstance(w.org, list) else str(w.org)
                if any(indicator in org_str.lower() for indicator in privacy_indicators):
                    has_privacy = 1
            
            features.update({
                'domain_age_days': domain_age,
                'has_whois_info': 1,
                'is_domain_registered': 1 if (w.creation_date or w.registrar) else 0,
                'registrar_length': registrar_length,
                'has_privacy_protection': has_privacy,
                'name_server_count': name_server_count,
            })
            
    except whois.parser.PywhoisError as e:
        features['is_domain_registered'] = 0
    except Exception as e:
        print(f"Error extracting metadata features for {url}: {e}")
    
    return features

# Test function
# def test_metadata_features():
#     """Test WHOIS metadata feature extraction"""
#     test_urls = [
#         "https://www.google.com",
#         "https://github.com",
#         "https://example.com",
#         "https://this-domain-definitely-does-not-exist-12345.com",
#         "https://localhost",
#         "https://127.0.0.1:8000",
#         "https://amazon.com",  # Often uses privacy protection
#         "https://wikipedia.org",
#     ]
    
#     for url in test_urls:
#         print(f"\n=== Testing: {url} ===")
#         features = extract_metadata_features(url)
#         for key, value in features.items():
#             print(f"{key}: {value}")
        
#         # Add a small delay to avoid rate limiting
#         import time
#         time.sleep(2)  # WHOIS lookups can be rate-limited

# if __name__ == "__main__":
#     test_metadata_features()