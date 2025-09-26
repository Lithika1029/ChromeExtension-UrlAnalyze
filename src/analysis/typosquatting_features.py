# analysis/typosquatting_features.py
import re
import tldextract
from difflib import SequenceMatcher
import logging
from urllib.parse import urlparse

# Popular legitimate domains that are commonly targeted
POPULAR_DOMAINS = {
    'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'netflix.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'paypal.com',
    'ebay.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'whatsapp.com',
    'tiktok.com', 'spotify.com', 'discord.com', 'zoom.us', 'slack.com',
    'dropbox.com', 'airbnb.com', 'uber.com', 'lyft.com', 'coinbase.com',
    'binance.com', 'wellsfargo.com', 'bankofamerica.com', 'chase.com',
    'citibank.com', 'capitalone.com', 'americanexpress.com', 'visa.com',
    'mastercard.com', 'outlook.com', 'gmail.com', 'yahoo.com', 'hotmail.com',
    'protonmail.com', 'icloud.com', 'aol.com', 'zoho.com', 'youtube.com',
    'twitch.tv', 'vimeo.com', 'dailymotion.com', 'wordpress.com', 'medium.com',
    'quora.com', 'pinterest.com', 'tumblr.com', 'flickr.com', 'imgur.com',
    'wikipedia.org', 'imdb.com', 'craigslist.org', 'booking.com', 'expedia.com',
    'tripadvisor.com', 'yelp.com', 'walmart.com', 'target.com', 'bestbuy.com',
    'homedepot.com', 'lowes.com', 'costco.com', 'kohls.com', 'macys.com',
    'nordstrom.com', 'sears.com', 'jcpenney.com', 'gap.com', 'oldnavy.com'
}

# Common homoglyph substitutions
HOMOGLYPHS = {
    'a': ['а', 'ɑ', 'α', 'а'],  # Cyrillic, Greek, etc.
    'b': ['Ь', 'ḅ', 'ḇ', 'ƅ'],
    'c': ['с', 'ϲ', 'ç', 'ć', 'ĉ'],  # Cyrillic, Greek
    'd': ['ԁ', 'ḋ', 'đ', 'ɗ'],
    'e': ['е', 'ё', 'ë', 'ē', 'ė', 'ę'],  # Cyrillic
    'g': ['ġ', 'ğ', 'ĝ', 'ǥ'],
    'h': ['һ', 'ḥ', 'ḫ', 'ĥ'],
    'i': ['і', 'ï', 'ī', 'į', 'ɨ'],  # Cyrillic
    'j': ['ј', 'ј', 'ĵ'],  # Cyrillic
    'k': ['κ', 'ķ', 'ǩ'],
    'l': ['ӏ', 'ḷ', 'ļ', 'ł'],
    'm': ['ṃ', 'ɱ'],
    'n': ['ń', 'ņ', 'ň', 'ŋ'],
    'o': ['о', 'ο', 'ō', 'ő', 'ơ'],  # Cyrillic, Greek
    'p': ['р', 'ṗ', 'ƥ'],  # Cyrillic
    'q': ['ԛ', 'ɋ'],
    'r': ['г', 'ṛ', 'ŕ', 'ř'],  # Cyrillic
    's': ['ѕ', 'ś', 'ŝ', 'ş'],  # Cyrillic
    'u': ['μ', 'ū', 'ŭ', 'ů', 'ű'],
    'v': ['ν', 'ѵ', 'ṽ'],
    'w': ['ω', 'ẁ', 'ẃ', 'ŵ'],
    'x': ['х', 'ҳ', 'ẍ'],  # Cyrillic
    'y': ['у', 'ý', 'ŷ', 'ÿ'],  # Cyrillic
    'z': ['ź', 'ż', 'ž', 'ƶ']
}

# Common typosquatting techniques
COMMON_TYPOS = {
    'additions': ['-login', '-secure', '-account', '-verify', '-update', '-signin', '-auth', '-bank', '-pay', '-service', '-portal', '-support', '-help', '-info', '-user', '-online', '-web', '-admin', '-access', '-check'],
    'replacements': [
        ('o', '0'), ('i', '1'), ('l', '1'), ('s', '5'), ('e', '3'),
        ('a', '4'), ('t', '7'), ('g', '9'), ('b', '8'), ('c', '('), ('d', 'cl'), ('m', 'nn'),
        ('u', 'v'), ('r', 'Я'), ('n', 'И'), ('y', '¥'), ('k', 'κ'), ('h', 'н'), ('f', 'ƒ'), ('p', 'ρ'), ('x', 'χ'), ('z', '2')
    ],
    'omissions': [  # Common character omissions
        'facebok', 'googel', 'yutube', 'paypall', 'amazoon', 'micorsoft', 'twiter', 'instgram', 'linkdin', 'whatsap',
        'netflik', 'spofity', 'discor', 'slak', 'tumbl', 'reddt', 'gitub', 'youtub', 'pintrst', 'vime',
        'dailymotin', 'wpres', 'medum', 'qora', 'flickr', 'imgur', 'wikpedia', 'imdbb', 'craigslist', 'bookingg',
        'expediaa', 'tripadvisr', 'yelp', 'walmrt', 'targt', 'bestbuyy', 'homedepott', 'lowess', 'costcoo', 'kohls', 'macys',
        'nordstrm', 'sears', 'jcpeny', 'gap', 'oldnavy', 'slcak'
    ],
    'transpositions': [  # Common transpositions
        'googel', 'facebok', 'yaho', 'ebya', 'amzon', 'twitte', 'instagarm', 'linkdein', 'paypl', 'amazno', 'facbook', 'micorsoft',
        'netfli', 'spofity', 'disocrd', 'slakc', 'tumblr', 'reddiit', 'gitbub', 'youtbue', 'pintrset', 'vimo', 'dailymotio', 'wpres',
        'medim', 'quora', 'flicrk', 'imurg', 'wikipeida', 'imdb', 'craigsist', 'bookng', 'expedia', 'tripadviosr', 'yelp', 'walmat',
        'targe', 'bestbuiy', 'homdepot', 'lows', 'costco', 'kohls', 'macys', 'nordstom'
    ]
}


def similarity_ratio(a, b):
    """Calculate similarity ratio between two strings"""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def contains_homoglyphs(domain):
    """Check if domain contains homoglyph characters"""
    homoglyph_count = 0
    suspicious_chars = []
    
    for char in domain:
        for original, substitutes in HOMOGLYPHS.items():
            if char in substitutes:
                homoglyph_count += 1
                suspicious_chars.append((char, original))
                break
    
    return homoglyph_count > 0, homoglyph_count, suspicious_chars


def detect_typosquatting(domain):
    """Detect various typosquatting techniques"""
    techniques_found = []
    confidence = 0.0
    
    # Check against popular domains
    for popular_domain in POPULAR_DOMAINS:
        similarity = similarity_ratio(domain, popular_domain)
        
        # High similarity but not exact match
        if 0.7 <= similarity < 0.95:
            techniques_found.append(f"Similar to '{popular_domain}' (similarity: {similarity:.2f})")
            confidence = max(confidence, similarity)
    
    # Check for character replacements (like o→0, i→1, etc.)
    for original, replacement in COMMON_TYPOS['replacements']:
        if replacement in domain and original not in domain:
            # Only flag if this makes it similar to a popular domain
            for popular_domain in POPULAR_DOMAINS:
                if original in popular_domain and replacement in domain:
                    techniques_found.append(f"Character replacement: '{replacement}' for '{original}' (mimicking '{popular_domain}')")
                    confidence = max(confidence, 0.8)
                    break
    
    # Check for common typos in popular domains
    domain_lower = domain.lower()
    for popular_domain in POPULAR_DOMAINS:
        popular_lower = popular_domain.lower()
        
        # Check for transpositions (google → googel)
        if len(domain_lower) == len(popular_lower):
            differences = sum(1 for a, b in zip(domain_lower, popular_lower) if a != b)
            if differences == 1 and similarity_ratio(domain_lower, popular_lower) > 0.8:
                techniques_found.append(f"Single character transposition of '{popular_domain}'")
                confidence = max(confidence, 0.9)
        
        # Check for omissions (facebook → facebok)
        if popular_lower in domain_lower and domain_lower != popular_lower:
            techniques_found.append(f"Contains but modifies '{popular_domain}'")
            confidence = max(confidence, 0.7)
    
    # Check for added words
    for addition in COMMON_TYPOS['additions']:
        if addition in domain:
            techniques_found.append(f"Suspicious word addition: '{addition}'")
            confidence = max(confidence, 0.6)
    
    return techniques_found, confidence


def extract_typosquatting_features(url):
    """Extract typosquatting and homoglyph features from URL"""
    try:
        # Extract domain
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Extract domain without TLD for analysis
        ext = tldextract.extract(url)
        domain_name = ext.domain
        full_domain = f"{ext.domain}.{ext.suffix}"
        
        features = {
            'typosquatting_detected': 0,
            'typosquatting_confidence': 0.0,
            'homoglyph_detected': 0,
            'homoglyph_count': 0,
            'suspicious_similarity': 0.0,
            'techniques_used': [],
            'homoglyph_details': [],
            'targeted_legitimate_domain': 'none'
        }
        
        # Homoglyph detection
        homoglyph_detected, homoglyph_count, suspicious_chars = contains_homoglyphs(domain)
        
        if homoglyph_detected:
            features['homoglyph_detected'] = 1
            features['homoglyph_count'] = homoglyph_count
            features['homoglyph_details'] = [f"{char}->{original}" for char, original in suspicious_chars]
        
        # Typosquatting detection
        techniques, confidence = detect_typosquatting(full_domain)
        
        if techniques:
            features['typosquatting_detected'] = 1
            features['typosquatting_confidence'] = confidence
            features['techniques_used'] = techniques
            
            # Calculate similarity to closest popular domain
            max_similarity = 0.0
            closest_domain = ""
            
            for popular_domain in POPULAR_DOMAINS:
                similarity = similarity_ratio(full_domain, popular_domain)
                if similarity > max_similarity:
                    max_similarity = similarity
                    closest_domain = popular_domain
            
            features['suspicious_similarity'] = max_similarity
            features['targeted_legitimate_domain'] = closest_domain
        
        # Additional heuristic: domain length vs popular domains
        avg_popular_length = sum(len(d) for d in POPULAR_DOMAINS) / len(POPULAR_DOMAINS)
        length_diff = abs(len(full_domain) - avg_popular_length)
        
        if length_diff > 10:  # Unusually long or short
            features['unusual_domain_length'] = 1
        else:
            features['unusual_domain_length'] = 0
        
        features['domain_length'] = len(full_domain)
        features['avg_popular_domain_length'] = avg_popular_length
        
        logging.debug(f"✅ Typosquatting features extracted for {domain}")
        return features
        
    except Exception as e:
        logging.error(f"❌ Typosquatting analysis error for {url}: {e}")
        return {
            'typosquatting_detected': 0,
            'typosquatting_confidence': 0.0,
            'homoglyph_detected': 0,
            'homoglyph_count': 0,
            'suspicious_similarity': 0.0,
            'techniques_used': [],
            'homoglyph_details': [],
            'targeted_legitimate_domain': 'none',
            'error': str(e)
        }
