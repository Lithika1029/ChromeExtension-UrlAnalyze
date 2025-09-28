# analysis/typosquatting_features.py
import tldextract
from difflib import SequenceMatcher
import re
import logging

def is_legitimate_subdomain(domain):
    """
    Check if domain is a legitimate subdomain of a popular domain
    """
    LEGITIMATE_SUBDOMAINS = {
        'google': ['support', 'docs', 'drive', 'mail', 'maps', 'play', 'news', 'photos', 'accounts', 'myaccount', 'chrome', 'firebase', 'cloud'],
        'facebook': ['business', 'developers', 'about', 'help', 'newsroom'],
        'amazon': ['aws', 'kindle', 'prime', 'fresh', 'sellercentral', 'advertising'],
        'microsoft': ['support', 'docs', 'learn', 'azure', 'technet', 'msdn'],
        'github': ['gist', 'help', 'education', 'enterprise'],
        'paypal': ['developer', 'business', 'manager'],
        'apple': ['support', 'developer', 'apps', 'books'],
        'youtube': ['studio', 'tv', 'kids'],
        'twitter': ['developer', 'business'],
        'instagram': ['developer', 'business'],
        'linkedin': ['learning', 'business', 'developer']
    }
    
    extracted = tldextract.extract(domain)
    main_domain = extracted.domain.lower()
    subdomain_parts = extracted.subdomain.lower().split('.') if extracted.subdomain else []
    
    if main_domain in LEGITIMATE_SUBDOMAINS:
        # If no subdomain, it's the main domain - legitimate
        if not extracted.subdomain:
            return True
        
        # Check if any subdomain part is in legitimate list
        for part in subdomain_parts:
            if part in LEGITIMATE_SUBDOMAINS[main_domain]:
                return True
    
    return False

def improved_typosquatting_detection(url):
    """
    Improved typosquatting detection that avoids false positives
    """
    try:
        extracted = tldextract.extract(url)
        domain_name = extracted.domain.lower()
        full_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        # Skip legitimate domains and subdomains
        if is_legitimate_subdomain(full_domain):
            return {
                'typosquatting_detected': 0,
                'typosquatting_confidence': 0.0,
                'targeted_legitimate_domain': 'none',
                'suspicious_similarity': 0.0,
                'techniques_used': [],
                'homoglyph_detected': 0,
                'homoglyph_count': 0,
                'homoglyph_details': [],
                'unusual_domain_length': 0,
                'domain_length': len(domain_name),
                'avg_popular_domain_length': 6.2,
                'reason': 'Legitimate subdomain of popular domain'
            }
        
        # List of popular domains to check against
        POPULAR_DOMAINS = [
            'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
            'twitter', 'instagram', 'linkedin', 'youtube', 'whatsapp', 'tiktok',
            'paypal', 'ebay', 'wikipedia', 'github', 'reddit', 'discord',
            'spotify', 'zoom', 'slack', 'dropbox', 'airbnb', 'uber'
        ]
        
        best_similarity = 0.0
        best_match = None
        techniques_used = []
        
        for popular_domain in POPULAR_DOMAINS:
            similarity = SequenceMatcher(None, domain_name, popular_domain).ratio()
            
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = popular_domain
        
        # Only consider it typosquatting if similarity is high but not exact
        # and it's not a legitimate subdomain
        is_typosquatting = (0.7 <= best_similarity < 0.95) and domain_name != best_match
        
        if is_typosquatting:
            # Analyze techniques used
            if len(domain_name) > len(best_match) + 2:
                techniques_used.append("Character addition")
            elif len(domain_name) < len(best_match) - 2:
                techniques_used.append("Character omission")
            
            # Check for character replacements
            common_replacements = [
                ('o', '0'), ('i', '1'), ('l', '1'), ('s', '5'), ('e', '3'),
                ('a', '4'), ('t', '7'), ('g', '9')
            ]
            
            for original, replacement in common_replacements:
                if replacement in domain_name and original not in domain_name:
                    if any(original in popular for popular in POPULAR_DOMAINS):
                        techniques_used.append(f"Character replacement: '{replacement}' for '{original}'")
                        break
            
            # Check for transpositions
            if len(domain_name) == len(best_match):
                diff_count = sum(1 for a, b in zip(domain_name, best_match) if a != b)
                if diff_count <= 2:
                    techniques_used.append("Character transposition")
        
        # Homoglyph detection
        homoglyph_patterns = [
            (r'[асԁеһіјӏорԗѕԝху]', 'cyrillic'),  # Cyrillic homoglyphs
            (r'[𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳]', 'bold'),
            (r'[𝒂𝒃𝒄𝒅𝒆𝒇𝒈𝒉𝒊𝒋𝒌𝒍𝒎𝒏𝒐𝒑𝒒𝒓𝒔𝒕𝒖𝒗𝒘𝒙𝒚𝒛]', 'italic'),
            (r'[𝗮𝗯𝗰𝗱𝗲𝗳𝗴𝗵𝗶𝗷𝗸𝗹𝗺𝗻𝗼𝗽𝗾𝗿𝘀𝘁𝘂𝘃𝘄𝘅𝘆𝘇]', 'sans'),
        ]
        
        homoglyph_detected = 0
        homoglyph_count = 0
        homoglyph_details = []
        
        for pattern, glyph_type in homoglyph_patterns:
            matches = re.findall(pattern, domain_name)
            if matches:
                homoglyph_detected = 1
                homoglyph_count += len(matches)
                homoglyph_details.append(f"{len(matches)} {glyph_type} homoglyph(s) found")
        
        # Domain length analysis
        avg_popular_length = 6.2  # Average length of popular domains
        unusual_length = 1 if abs(len(domain_name) - avg_popular_length) > 3 else 0
        
        confidence = min(best_similarity * 1.2, 1.0) if is_typosquatting else 0.0
        
        return {
            'typosquatting_detected': 1 if is_typosquatting else 0,
            'typosquatting_confidence': round(confidence, 4),
            'targeted_legitimate_domain': best_match if is_typosquatting else 'none',
            'suspicious_similarity': round(best_similarity, 4),
            'techniques_used': techniques_used,
            'homoglyph_detected': homoglyph_detected,
            'homoglyph_count': homoglyph_count,
            'homoglyph_details': homoglyph_details,
            'unusual_domain_length': unusual_length,
            'domain_length': len(domain_name),
            'avg_popular_domain_length': avg_popular_length,
            'reason': 'Typosquatting detected' if is_typosquatting else 'No significant similarity'
        }
        
    except Exception as e:
        logging.error(f"Typosquatting detection error: {e}")
        return {
            'typosquatting_detected': 0,
            'typosquatting_confidence': 0.0,
            'targeted_legitimate_domain': 'none',
            'suspicious_similarity': 0.0,
            'techniques_used': [],
            'homoglyph_detected': 0,
            'homoglyph_count': 0,
            'homoglyph_details': [],
            'unusual_domain_length': 0,
            'domain_length': 0,
            'avg_popular_domain_length': 6.2,
            'reason': f'Error: {str(e)}'
        }

def extract_typosquatting_features(url):
    """
    Extract typosquatting features for the main analysis
    """
    return improved_typosquatting_detection(url)