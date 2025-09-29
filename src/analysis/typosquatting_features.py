# analysis/typosquatting_features.py
import tldextract
from difflib import SequenceMatcher
import re
import logging

def extract_typosquatting_features(url):
    """
    Robust typosquatting detection that only flags actual typosquatting attempts
    """
    try:
        # Default safe response
        default_features = {
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
            'reason': 'No typosquatting detected'
        }
        
        extracted = tldextract.extract(url)
        domain_name = extracted.domain.lower()
        
        # Skip if no domain name extracted
        if not domain_name or len(domain_name) < 2:
            default_features['reason'] = 'No domain name extracted'
            return default_features
        
        # 1. FIRST FILTER: Check if this is obviously a legitimate domain
        if _is_obviously_legitimate(domain_name, extracted):
            default_features['reason'] = 'Legitimate domain characteristics'
            return default_features
        
        # 2. SECOND FILTER: Check domain characteristics that indicate legitimacy
        if _has_legitimate_characteristics(domain_name):
            default_features['reason'] = 'Has legitimate domain patterns'
            return default_features
        
        # 3. ONLY NOW check for typosquatting against popular domains
        popular_domains = _get_popular_domains_list()
        analysis = _analyze_typosquatting_attempt(domain_name, popular_domains)
        
        # 4. FINAL VALIDATION: Apply strict thresholds
        if analysis['is_typosquatting']:
            return {
                'typosquatting_detected': 1,
                'typosquatting_confidence': analysis['confidence'],
                'targeted_legitimate_domain': analysis['target'],
                'suspicious_similarity': analysis['similarity'],
                'techniques_used': analysis['techniques'],
                'homoglyph_detected': analysis['homoglyph_detected'],
                'homoglyph_count': analysis['homoglyph_count'],
                'homoglyph_details': analysis['homoglyph_details'],
                'unusual_domain_length': analysis['unusual_length'],
                'domain_length': len(domain_name),
                'avg_popular_domain_length': 6.2,
                'reason': analysis['reason']
            }
        else:
            default_features['reason'] = analysis['reason']
            default_features['domain_length'] = len(domain_name)
            default_features['suspicious_similarity'] = analysis['similarity']
            return default_features
        
    except Exception as e:
        logging.error(f"Typosquatting detection error for {url}: {e}")
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
            'reason': f'Error in analysis: {str(e)}'
        }

def _is_obviously_legitimate(domain_name, extracted):
    """
    Filter out obviously legitimate domains before typosquatting analysis
    """
    # Common legitimate TLDs for established companies
    established_tlds = {'com', 'org', 'net', 'edu', 'gov', 'io'}
    
    # If it's a common TLD and domain looks normal, skip typosquatting check
    if extracted.suffix in established_tlds:
        # Check if domain name looks like a real word or brand
        if _looks_like_real_word(domain_name):
            return True
        
        # Check if it's a compound word (common in legitimate domains)
        if _is_compound_word(domain_name):
            return True
    
    return False

def _has_legitimate_characteristics(domain_name):
    """
    Check if domain has characteristics of legitimate websites
    """
    # Length-based legitimacy (very short or very long domains are often legitimate)
    if len(domain_name) < 3 or len(domain_name) > 15:
        return True
    
    # Contains common legitimate patterns
    legitimate_patterns = [
        r'^[a-z]{2,}app$',  # somethingapp
        r'^[a-z]{2,}ly$',   # somethingly
        r'^[a-z]{2,}fy$',   # somethingfy
        r'^[a-z]{2,}ify$',  # somethingify
        r'^get[a-z]{2,}$',  # getsomething
        r'^my[a-z]{2,}$',   # mysomething
        r'^[a-z]{2,}hub$',  # somethinghub
        r'^[a-z]{2,}flow$', # somethingflow
        r'^[a-z]{2,}base$', # somethingbase
    ]
    
    for pattern in legitimate_patterns:
        if re.match(pattern, domain_name):
            return True
    
    return False

def _looks_like_real_word(domain_name):
    """
    Check if domain name looks like a real English word or common brand
    """
    # Common English words that are often domains
    common_words = {
        'reddit', 'okta', 'medium', 'quora', 'target', 'hotmail', 'gmail',
        'book', 'shop', 'store', 'news', 'blog', 'mail', 'chat', 'video',
        'music', 'photo', 'cloud', 'data', 'tech', 'web', 'net', 'online',
        'digital', 'global', 'world', 'service', 'system', 'solution'
    }
    
    if domain_name in common_words:
        return True
    
    # Check if it's a recognizable brand-like name
    if len(domain_name) >= 4 and domain_name.isalpha():
        vowel_count = sum(1 for char in domain_name if char in 'aeiou')
        consonant_count = len(domain_name) - vowel_count
        
        # Real words typically have reasonable vowel-consonant ratio
        if vowel_count >= 1 and consonant_count >= 2:
            return True
    
    return False

def _is_compound_word(domain_name):
    """
    Check if domain is a compound of common words
    """
    common_prefixes = {'face', 'you', 'link', 'net', 'cloud', 'data', 'web', 'smart'}
    common_suffixes = {'book', 'tube', 'edin', 'flix', 'gram', 'hub', 'base', 'flow'}
    
    for prefix in common_prefixes:
        if domain_name.startswith(prefix) and len(domain_name) > len(prefix):
            return True
    
    for suffix in common_suffixes:
        if domain_name.endswith(suffix) and len(domain_name) > len(suffix):
            return True
    
    return False

def _get_popular_domains_list():
    """
    Return a list of popular domain names (without TLDs)
    """
    return [
        'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
        'twitter', 'instagram', 'linkedin', 'youtube', 'whatsapp', 'tiktok',
        'paypal', 'ebay', 'wikipedia', 'github', 'reddit', 'discord',
        'spotify', 'zoom', 'slack', 'dropbox', 'airbnb', 'uber', 'okta',
        'hotmail', 'gmail', 'yahoo', 'outlook', 'medium', 'quora', 'target'
    ]

def _analyze_typosquatting_attempt(domain_name, popular_domains):
    """
    Core typosquatting analysis with strict criteria
    """
    best_similarity = 0.0
    best_match = None
    
    for popular_domain in popular_domains:
        similarity = SequenceMatcher(None, domain_name, popular_domain).ratio()
        
        if similarity > best_similarity:
            best_similarity = similarity
            best_match = popular_domain
    
    # STRICT CRITERIA for typosquatting detection
    is_typosquatting = False
    techniques = []
    confidence = 0.0
    reason = "No significant similarity or techniques detected"
    
    # Only proceed if similarity is in the suspicious range
    if 0.75 <= best_similarity < 0.95 and domain_name != best_match:
        techniques = _detect_typosquatting_techniques(domain_name, best_match)
        
        # REQUIREMENT: Must have at least 2 clear typosquatting techniques
        if len(techniques) >= 2:
            is_typosquatting = True
            confidence = min(best_similarity * 1.3, 1.0)
            reason = f"Multiple typosquatting techniques detected targeting {best_match}"
        elif len(techniques) == 1 and 'homoglyph' in str(techniques[0]).lower():
            # Homoglyph alone is enough if confidence is high
            is_typosquatting = True
            confidence = min(best_similarity * 1.5, 1.0)
            reason = f"Homoglyph attack detected targeting {best_match}"
        else:
            reason = f"Similarity to {best_match} but insufficient techniques ({len(techniques)} found)"
    elif best_similarity >= 0.95:
        reason = f"Very high similarity to {best_match} but likely legitimate"
    elif best_similarity > 0:
        reason = f"Low similarity to {best_match} ({best_similarity:.2f}) - not suspicious"
    
    # Homoglyph analysis
    homoglyph_detected, homoglyph_count, homoglyph_details = _detect_homoglyphs(domain_name)
    
    # Domain length analysis
    unusual_length = 1 if abs(len(domain_name) - 6.2) > 4 else 0
    
    return {
        'is_typosquatting': is_typosquatting,
        'confidence': round(confidence, 4),
        'target': best_match if is_typosquatting else 'none',
        'similarity': round(best_similarity, 4),
        'techniques': techniques,
        'homoglyph_detected': homoglyph_detected,
        'homoglyph_count': homoglyph_count,
        'homoglyph_details': homoglyph_details,
        'unusual_length': unusual_length,
        'reason': reason
    }

def _detect_typosquatting_techniques(domain_name, target_domain):
    """
    Detect specific typosquatting techniques with evidence
    """
    techniques = []
    
    # 1. Character addition/omission with significant difference
    length_diff = len(domain_name) - len(target_domain)
    if length_diff >= 3:
        techniques.append(f"Excessive character addition (+{length_diff})")
    elif length_diff <= -3:
        techniques.append(f"Excessive character omission ({length_diff})")
    
    # 2. Character substitution with common typos
    common_typos = {
        'o': '0', 'i': '1', 'l': '1', 's': '5', 'e': '3',
        'a': '4', 't': '7', 'g': '9', 'm': 'rn', 'w': 'vv'
    }
    
    for original, replacement in common_typos.items():
        if replacement in domain_name and original in target_domain:
            if domain_name.count(replacement) > target_domain.count(original):
                techniques.append(f"Character substitution: '{replacement}' for '{original}'")
                break
    
    # 3. Transposition detection
    if len(domain_name) == len(target_domain):
        diff_positions = [i for i, (a, b) in enumerate(zip(domain_name, target_domain)) if a != b]
        if len(diff_positions) == 2:
            # Check if it's a simple swap
            pos1, pos2 = diff_positions
            if (domain_name[pos1] == target_domain[pos2] and 
                domain_name[pos2] == target_domain[pos1]):
                techniques.append("Character transposition")
    
    # 4. Double letter manipulation
    if _has_double_letter_manipulation(domain_name, target_domain):
        techniques.append("Double letter manipulation")
    
    return techniques

def _detect_homoglyphs(domain_name):
    """
    Detect homoglyph characters with strict criteria
    """
    # Only flag obvious homoglyph attacks
    homoglyph_patterns = [
        (r'[асьеіјорху]', 'cyrillic'),  # Cyrillic homoglyphs
    ]
    
    homoglyph_detected = 0
    homoglyph_count = 0
    homoglyph_details = []
    
    for pattern, glyph_type in homoglyph_patterns:
        matches = re.findall(pattern, domain_name)
        if matches:
            homoglyph_count += len(matches)
            # Only flag if multiple homoglyphs found
            if homoglyph_count >= 2:
                homoglyph_detected = 1
                homoglyph_details.append(f"{len(matches)} {glyph_type} homoglyph(s)")
    
    return homoglyph_detected, homoglyph_count, homoglyph_details

def _has_double_letter_manipulation(domain_name, target_domain):
    """
    Check for double letter addition/removal
    """
    import itertools
    
    def get_letter_groups(s):
        return [(char, len(list(group))) for char, group in itertools.groupby(s)]
    
    domain_groups = get_letter_groups(domain_name)
    target_groups = get_letter_groups(target_domain)
    
    # Check if there's a significant difference in letter grouping
    if len(domain_groups) == len(target_groups):
        diff_count = 0
        for (char1, count1), (char2, count2) in zip(domain_groups, target_groups):
            if char1 == char2 and abs(count1 - count2) >= 2:
                diff_count += 1
        return diff_count > 0
    
    return False