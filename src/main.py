# main.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re
from urllib.parse import urlparse
import tldextract
import time
import logging
from datetime import datetime
import sys
import math
from collections import Counter

# Import configuration
from app.config import current_config as Config

# Import analysis modules
from analysis.dns_features import extract_dns_features_advanced
from analysis.header_features import extract_header_features
from analysis.meta_features import extract_metadata_features
from analysis.ssl_features import extract_ssl_features
from analysis.url_features import extract_url_features
from analysis.typosquatting_features import extract_typosquatting_features

# Import model utilities
from modals.model_util import get_model_manager

# Create Flask app instance
app = Flask(__name__)
CORS(app, origins=Config.CORS_ORIGINS)

# Global detector instance
phishing_detector = None

def ensure_directories():
    """Ensure all required directories exist"""
    directories = [
        'logs',
        'models/saved_models',
        'models/datasets',
        'models/notebooks'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"📁 Ensured directory: {directory}")


class AdvancedPhishingDetector:
    def __init__(self):
        self.model_manager = get_model_manager()
        self.analysis_modules = Config.ANALYSIS_CONFIG
        self.risk_thresholds = Config.RISK_THRESHOLDS
        self.cache = {}
        self.request_count = 0
        logging.info("✅ Advanced phishing detector initialized!")
    
    def get_enabled_modules(self):
        """Get list of enabled analysis modules"""
        return [module for module, config in self.analysis_modules.items() 
                if config.get('enabled', False)]
    
    def extract_comprehensive_features(self, url):
        """Extract features from all enabled analysis modules"""
        features = {}
        module_status = {}
        extraction_times = {}
        
        # URL Structure Features (always enabled)
        start_time = time.time()
        try:
            url_features = extract_url_features(url)
            features.update({f'url_{k}': v for k, v in url_features.items()})
            module_status['url_analysis'] = 'success'
            extraction_times['url_analysis'] = round(time.time() - start_time, 4)
            logging.debug("✅ URL features extracted")
        except Exception as e:
            logging.error(f"❌ URL analysis error: {e}")
            module_status['url_analysis'] = f'error: {str(e)}'
            extraction_times['url_analysis'] = 0
        
        # DNS Features
        if self.analysis_modules.get('dns', {}).get('enabled', False):
            start_time = time.time()
            try:
                dns_features = extract_dns_features_advanced(url)
                features.update({f'dns_{k}': v for k, v in dns_features.items()})
                module_status['dns_analysis'] = 'success'
                extraction_times['dns_analysis'] = round(time.time() - start_time, 4)
                logging.debug("✅ DNS features extracted")
            except Exception as e:
                logging.error(f"❌ DNS analysis error: {e}")
                module_status['dns_analysis'] = f'error: {str(e)}'
                extraction_times['dns_analysis'] = 0
        
        # Header Features
        if self.analysis_modules.get('headers', {}).get('enabled', False):
            start_time = time.time()
            try:
                header_features = extract_header_features(url)
                features.update({f'header_{k}': v for k, v in header_features.items()})
                module_status['header_analysis'] = 'success'
                extraction_times['header_analysis'] = round(time.time() - start_time, 4)
                logging.debug("✅ Header features extracted")
            except Exception as e:
                logging.error(f"❌ Header analysis error: {e}")
                module_status['header_analysis'] = f'error: {str(e)}'
                extraction_times['header_analysis'] = 0
        
        # SSL Features
        if self.analysis_modules.get('ssl', {}).get('enabled', False):
            start_time = time.time()
            try:
                ssl_features, ssl_success = extract_ssl_features(url)
                features.update({f'ssl_{k}': v for k, v in ssl_features.items()})
                module_status['ssl_analysis'] = 'success' if ssl_success else 'ssl_failed'
                extraction_times['ssl_analysis'] = round(time.time() - start_time, 4)
                logging.debug("✅ SSL features extracted")
            except Exception as e:
                logging.error(f"❌ SSL analysis error: {e}")
                module_status['ssl_analysis'] = f'error: {str(e)}'
                extraction_times['ssl_analysis'] = 0
        
        # Metadata Features
        if self.analysis_modules.get('metadata', {}).get('enabled', False):
            start_time = time.time()
            try:
                meta_features = extract_metadata_features(url)
                features.update({f'meta_{k}': v for k, v in meta_features.items()})
                module_status['metadata_analysis'] = 'success'
                extraction_times['metadata_analysis'] = round(time.time() - start_time, 4)
                logging.debug("✅ Metadata features extracted")
            except Exception as e:
                logging.error(f"❌ Metadata analysis error: {e}")
                module_status['metadata_analysis'] = f'error: {str(e)}'
                extraction_times['metadata_analysis'] = 0
        
        # Typosquatting Features
        if self.analysis_modules.get('typosquatting', {}).get('enabled', False):
            start_time = time.time()
            try:
                typosquatting_features = extract_typosquatting_features(url)
                features.update({f'typo_{k}': v for k, v in typosquatting_features.items()})
                module_status['typosquatting_analysis'] = 'success'
                extraction_times['typosquatting_analysis'] = round(time.time() - start_time, 4)
                logging.debug("✅ Typosquatting features extracted")
            except Exception as e:
                logging.error(f"❌ Typosquatting analysis error: {e}")
                module_status['typosquatting_analysis'] = f'error: {str(e)}'
                extraction_times['typosquatting_analysis'] = 0
        
        return features, module_status, extraction_times
    
    def rule_based_analysis(self, url, features):
        """Enhanced rule-based analysis with comprehensive typosquatting detection"""
        score = 0.0
        rules_triggered = []
        rule_details = []

        # Scoring buckets / weights (tunable)
        W = {
            'ip_in_url': 30,
            'shortener': 35,
            'very_long_url': 15,
            'long_url': 5,
            'many_subdomains': 12,
            'suspicious_tld': 60,
            'suspicious_keyword': 60,
            'high_entropy_domain': 15,
            'no_dns': 25,
            'slow_dns': 12,
            'no_ssl': 40,
            'expired_ssl': 30,
            'new_domain_30': 30,
            'new_domain_365': 12,
            'missing_security_headers': 45,
            'excess_redirects': 10,
            'many_name_servers_low': 25,
            'privacy_whois': 10,
            'server_header_full': 2,
            # Typosquatting weights
            'homoglyph_detected': 30,
            'typosquatting_detected': 45,
            'high_similarity': 20,
            'unusual_length': 10,
            'character_replacement': 25,
            'addition_technique': 15,
            'omission_technique': 20
        }

        # Helper functions
        def contains_ip(u):
            m = re.search(r'//(\[?[0-9a-fA-F:\.]+\]?)(:|/|$)', u)
            return bool(m)

        def is_shortened(u):
            shorteners = {
                "bit.ly", "tinyurl.com", "t.co", "tiny.cc", "goo.gl", "ow.ly", "buff.ly",
                "is.gd", "cutt.ly", "rb.gy", "trib.al", "rebrand.ly", "shorturl.at",
                "soo.gd", "shorte.st", "mcaf.ee", "adf.ly", "bc.vc", "clk.im", "ity.im",
                "q.gs", "t.ly", "u.to", "x.co", "s.id", "zi.mu", "po.st", "surl.co", "clicky.me",
                "urlzs.com", "v.gd", "yep.it", "linkzip.net", "tiny.ie", "url.ie", "soo.it",
                "soo.gd", "cutt.us", "dft.ba", "fur.ly", "gg.gg", "kutt.it", "lnkd.in", "shar.es",
                "shrinkearn.com", "shrinkme.io", "short.cm", "shorte.st", "sk.gy", "smurl.name",
                "srt.am", "t2m.io", "tini.cc", "tr.im", "u.bb", "v.ht", "vb.ly", "viralurl.com",
                "wee.my", "wphurl.co", "y2u.be", "zi.pe", "zipmyurl.com", "1url.com", "2.gp",
                "2big.at", "2tu.us", "3.ly", "4sq.com", "7.ly", "9nl.me", "any.gs", "b23.ru",
                "bcool.bz", "bctiny.com", "bityli.com", "bl.ink", "boomurl.in", "bravo.ly",
                "cl.lk", "dai.ly", "dflnk.co", "dld.bz", "eb2.co", "fb.me", "fb.com", "fbshort.com",
                "flic.kr", "fly2.ws", "go2l.ink", "go2url.me", "huff.to", "j.mp", "ln.is", "lnk.co",
                "lnkd.in", "mgid.co", "moz.com", "ow.ly", "pnt.me", "qr.ae", "rb.gy", "soo.gd",
                "soourl.com", "sub.ly", "shurl.net", "surl.co", "t.co", "tiny.cc", "tiny.pl", "tl.gd",
                "urlshort.net", "vzturl.com", "wp.me", "x.co", "yep.it", "youtu.be", "zpr.io", "zws.im"
            }
            try:
                netloc = urlparse(u).netloc.lower()
                for s in shorteners:
                    if s in netloc:
                        return True
            except Exception:
                return False
            return False

        def count_subdomains(u):
            try:
                ext = tldextract.extract(u)
                sub = ext.subdomain or ''
                if sub == '':
                    return 0
                return len(sub.split('.'))
            except Exception:
                return 0

        def domain_entropy(domain):
            if not domain:
                return 0.0
            counts = Counter(domain)
            length = len(domain)
            ent = 0.0
            for c in counts.values():
                p = c / length
                ent -= p * math.log2(p)
            return ent

        def suspicious_tld_check(u):
            suspicious = {
                'tk','ml','ga','cf','gq','country','xyz','top','work','click','icu','pw',
                'site','online','tech','win','bid','men','loan','vip','party','stream','date',
                'download','link','buzz','review','support','cheap','fun','host','space','trade',
                'bet','live','news','press','chat','zone','club','life','world','store','website',
                'center','digital','today','clicks','offers','games','network','solutions','clickme',
                'email','help','account','security','online','shop','market','sale','promo','bonus',
                'free','money','gift','trial','win','prize','deal','fast','credit','loan','bank',
                'insurance','ticket','ticketing','lottery','casino','betting','reward','survey','earn',
                'ads','advert','promo','shopper','sale','coupon','discount','voucher','cash','pay',
                'wallet','exchange','finance','crypto','token','coin','blockchain','investment',
                'investment','fund','loaner','loans','mortgage','hack','hackers','virus','malware',
                'phish','ransom','exploit','darkweb','underground','blackhat','cheat','cheats','fraud',
                'scam','fake','tracker','spy','monitor','keylogger','remote','unblock','bypass','proxy',
                'vpn','tor','hidden','secret','anonymous'
            }
            try:
                ext = tldextract.extract(u)
                return (ext.suffix or '').lower() in suspicious
            except Exception:
                return False

        def suspicious_keywords_present(u):
            keywords = [
                'login','signin','secure','account','update','ebayisapi','banking','verify',
                'confirm','pay','wallet','payment','phishing','malware','support','help','password',
                'reset','recover','access','security','alert','notification','blocked','suspend','unlock',
                'activation','confirmemail','credit','debit','transfer','transaction','funds','money',
                'billing','invoice','receipt','statement','charge','refund','claim','reward','offer',
                'bonus','gift','promotion','coupon','discount','sale','deal','free','trial','download',
                'install','setup','updateapp','app','software','plugin','extension','link','click','redirect',
                'shortcut','verifyidentity','identity','passport','social','profile','bank','atm','loan',
                'mortgage','insurance','tax','irs','paypal','stripe','bitcoin','crypto','token','blockchain',
                'coin','investment','fund','loaner','lottery','prize','win','winner','casino','betting','bet',
                'earn','survey','questionnaire','ads','advertisement','promotion','clickhere','open','view',
                'confirmaccount','safepay','securepay','verifyaccount','updateaccount','accountupdate','accountverify',
                'signinaccount','loginaccount','loginpage','securitycheck','securityupdate','securelogin','securepage',
                'creditcard','cvv','pin','ssn','personal','information','identitytheft','hack','hacker','exploit','ransom',
                'virus','trojan','spyware','keylogger','malicious','danger','threat','warning','alertmessage','blockedaccess',
                'restricted','illegal','unauthorized','session','timeout','expired','error','failure','issue','problem','resolve',
                'fix','helpdesk','supportticket','contact','customer','service','assistance','agent','verifyidentity','confirmemailaddress',
                'updateprofile','changepassword','passwordreset','recoveraccount','unlockaccount','activationlink','securelink',
                'twofactor','2fa','authentication','auth','securetoken','securityquestion','captcha','challenge','response',
                'vpn','proxy','unblock','bypass','hidden','anonymous','darkweb','underground','blackhat','cheat','cheats',
                'fraud','scam','fake','tracker','spy','monitor','remote','unauthorizedaccess','hacktool','malwaretool','exploitkit',
                'phishingpage','phishingsite','maliciouslink','dangerous','threatalert','warningmessage','alertemail','securityalert',
                'criticalupdate','systemupdate','softwareupdate','appupdate','browserupdate','flashupdate','javaupdate','activexupdate',
                'accountalert','bankalert','paymentalert','transactionalert','fraudalert','unauthorizedtransaction','secureportal','securewebsite',
                'loginverify','signinverify','confirmtransaction','verifytransaction','confirmpayment','verifyfunds','accountsecurity',
                'securitynotice','securitywarning','securityupdate','protectaccount','protectidentity','identityprotection','dataprotection',
                'personaldata','databreach','privacyalert','cybersecurity','cyberattack','phishalert','malwarealert','ransomware','spyalert'
            ]
            low = u.lower()
            for kw in keywords:
                if kw in low:
                    return True, kw
            return False, None

        # ADD THIS MISSING HELPER FUNCTION
        def similarity_ratio(a, b):
            """Calculate similarity ratio between two strings"""
            from difflib import SequenceMatcher
            return SequenceMatcher(None, a.lower(), b.lower()).ratio()

        # Start rules ----------------------------------------------------------
        # URL length
        url_len = len(url or "")
        if url_len > 180:
            score += W['very_long_url']
            rules_triggered.append("Very long URL")
            rule_details.append(f"URL length: {url_len} (threshold: 180)")
        elif url_len > 100:
            score += W['long_url']
            rules_triggered.append("Long URL")
            rule_details.append(f"URL length: {url_len} (threshold: 100)")

        # IP in URL
        if contains_ip(url):
            score += W['ip_in_url']
            rules_triggered.append("IP address used in URL")
            rule_details.append("URL uses raw IP instead of domain")

        # Shortener detection
        if is_shortened(url):
            score += W['shortener']
            rules_triggered.append("URL Shortener detected")
            rule_details.append("URL uses known URL shortening service")

        # Subdomain depth
        sub_count = count_subdomains(url)
        if sub_count >= 4:
            score += W['many_subdomains']
            rules_triggered.append("Many subdomains")
            rule_details.append(f"Subdomain count: {sub_count}")

        # Suspicious TLDs
        if suspicious_tld_check(url):
            score += W['suspicious_tld']
            rules_triggered.append("Suspicious TLD")
            rule_details.append("TLD is commonly abused in phishing")

        # Trusted domain phishing boost
        trusted_domains = [
            "google.com","facebook.com","amazon.com","apple.com","microsoft.com",
            "netflix.com","twitter.com","instagram.com","linkedin.com","paypal.com",
            "ebay.com","github.com","stackoverflow.com","reddit.com","whatsapp.com",
            "tiktok.com","spotify.com","discord.com","zoom.us","slack.com",
            "dropbox.com","airbnb.com","uber.com","lyft.com","coinbase.com"
        ]

        try:
            ext = tldextract.extract(url)
            full_domain = f"{ext.domain}.{ext.suffix}"
            
            # Check if there are suspicious keywords in the path
            parsed_url = urlparse(url)
            path_lower = parsed_url.path.lower()
            
            suspicious_keywords = [
                'login','signin','secure','account','update','banking','verify',
                'confirm','pay','wallet','payment','password','reset','recover'
            ]
            
            has_suspicious_path = any(keyword in path_lower for keyword in suspicious_keywords)
            
            if full_domain in trusted_domains and (is_shortened(url) or has_suspicious_path):
                score += 25
                rules_triggered.append("Phishing pattern on trusted domain")
                rule_details.append("Trusted domain with suspicious patterns detected")
        except Exception as e:
            logging.debug(f"Trusted domain check failed: {e}")

        # Suspicious keywords in path/domain
        sk_present, sk = suspicious_keywords_present(url)
        if sk_present:
            score += W['suspicious_keyword']
            rules_triggered.append("Suspicious keyword in URL")
            rule_details.append(f"Keyword: {sk}")

        # High-entropy domains (random-looking)
        try:
            ext = tldextract.extract(url)
            domain_only = (ext.domain or "") + (ext.suffix or "")
            ent = domain_entropy(domain_only)
            if ent > 3.5:
                score += W['high_entropy_domain']
                rules_triggered.append("High entropy domain (likely random)")
                rule_details.append(f"Domain entropy: {ent:.2f}")
        except Exception:
            pass

        # DNS checks
        dns_has = features.get('dns_has_dns_record', None)
        if dns_has == 0:
            score += W['no_dns']
            rules_triggered.append("No DNS record")
            rule_details.append("DNS lookup returned no records")
        dns_time = features.get('dns_dns_response_time', 0)
        if dns_time and dns_time > 3.0:
            score += W['slow_dns']
            rules_triggered.append("Slow DNS response")
            rule_details.append(f"DNS response time: {dns_time}s")

        # SSL checks
        if features.get('ssl_has_ssl', 0) == 0:
            score += W['no_ssl']
            rules_triggered.append("No SSL certificate")
            rule_details.append("Server uses HTTP or SSL handshake failed")
        elif features.get('ssl_ssl_cert_expired', 0) == 1:
            score += W['expired_ssl']
            rules_triggered.append("Expired SSL cert")
            rule_details.append("SSL certificate expiration detected")

        # Metadata / WHOIS
        domain_age = features.get('meta_domain_age_days', 0)
        if domain_age and domain_age > 0 and domain_age < 30:
            score += W['new_domain_30']
            rules_triggered.append("New domain (<30 days)")
            rule_details.append(f"Domain age: {domain_age} days")
        elif domain_age and domain_age > 0 and domain_age < 365:
            score += W['new_domain_365']
            rules_triggered.append("Relatively new domain (<1 year)")
            rule_details.append(f"Domain age: {domain_age} days")

        # WHOIS privacy indicates potential obfuscation
        if features.get('meta_has_privacy_protection', 0) == 1:
            score += W['privacy_whois']
            rules_triggered.append("WHOIS privacy enabled")
            rule_details.append("WHOIS privacy/protection detected")

        # Header-based rules
        if features.get('header_has_x_frame_options', 0) == 0:
            score += W['missing_security_headers']
            rules_triggered.append("Missing security headers")
            rule_details.append("X-Frame-Options header missing")

        redirect_count = features.get('header_redirect_count', 0)
        try:
            redirect_count = int(redirect_count or 0)
        except Exception:
            redirect_count = 0
        if redirect_count > 5:
            score += W['excess_redirects']
            rules_triggered.append("Excessive redirects")
            rule_details.append(f"Redirects: {redirect_count}")

        # Name server / registrar oddities
        ns_count = features.get('meta_name_server_count', 0)
        if ns_count and ns_count < 2:
            score += W['many_name_servers_low']
            rules_triggered.append("Few name servers")
            rule_details.append(f"Name servers: {ns_count}")

        # Minor signals (server header presence)
        if features.get('header_has_server_header', 0) == 1:
            score += W['server_header_full']
            rule_details.append("Server header present (info leakage)")

        # Enhanced Typosquatting and Homoglyph detection
        homoglyph_detected = features.get('typo_homoglyph_detected', 0)
        typosquatting_detected = features.get('typo_typosquatting_detected', 0)
        similarity_score = features.get('typo_suspicious_similarity', 0.0)
        targeted_domain = features.get('typo_targeted_legitimate_domain', 'none')
        techniques_used = features.get('typo_techniques_used', [])
        
        if homoglyph_detected == 1:
            homoglyph_count = features.get('typo_homoglyph_count', 0)
            score += W['homoglyph_detected']
            rules_triggered.append("Homoglyph characters detected")
            rule_details.append(f"Found {homoglyph_count} homoglyph characters")
        
        if typosquatting_detected == 1:
            confidence = features.get('typo_typosquatting_confidence', 0.0)
            score += W['typosquatting_detected']
            
            if targeted_domain != 'none':
                rules_triggered.append(f"Typosquatting detected targeting {targeted_domain}")
                rule_details.append(f"Confidence: {confidence:.2f}, Techniques: {len(techniques_used)}")
            else:
                rules_triggered.append("Typosquatting detected")
                rule_details.append(f"Confidence: {confidence:.2f}")
            
            # Analyze specific techniques
            for technique in techniques_used:
                if 'replacement' in technique.lower():
                    score += W['character_replacement']
                elif 'addition' in technique.lower():
                    score += W['addition_technique']
                elif 'omission' in technique.lower() or 'transposition' in technique.lower():
                    score += W['omission_technique']
            
            # Add technique details
            for technique in techniques_used[:3]:
                rule_details.append(f"- {technique}")
        
        if similarity_score > 0.7:
            closest_domain = features.get('typo_targeted_legitimate_domain', 'unknown')
            score += W['high_similarity']
            rules_triggered.append("High similarity to legitimate domain")
            rule_details.append(f"Similarity: {similarity_score:.2f} to {closest_domain}")
        
        if features.get('typo_unusual_domain_length', 0) == 1:
            domain_len = features.get('typo_domain_length', 0)
            avg_len = features.get('typo_avg_popular_domain_length', 0)
            score += W['unusual_length']
            rules_triggered.append("Unusual domain length")
            rule_details.append(f"Domain length: {domain_len} (avg: {avg_len:.1f})")

        # Character replacement detection for common patterns
        common_replacements = [
            ('o', '0'), ('i', '1'), ('l', '1'), ('s', '5'), ('e', '3'),
            ('a', '4'), ('t', '7'), ('g', '9'), ('m', 'rn'), ('w', 'vv')
        ]
        
        try:
            ext = tldextract.extract(url)
            domain_name = ext.domain.lower()
            
            for original, replacement in common_replacements:
                if replacement in domain_name and original not in domain_name:
                    # Check if this makes it similar to a popular domain
                    for popular_domain in trusted_domains:
                        popular_name = popular_domain.split('.')[0].lower()
                        if original in popular_name and similarity_ratio(domain_name, popular_name) > 0.7:
                            score += W['character_replacement']
                            rules_triggered.append(f"Character replacement detected: '{replacement}' for '{original}'")
                            rule_details.append(f"Potential mimic of '{popular_domain}'")
                            break
        except Exception:
            pass

        # Normalize score
        max_score = 250.0  # Increased to account for enhanced typosquatting detection
        rule_probability = min(score/max_score, 1.0)

        return {
            "rule_score": round(score, 2),
            "rule_probability": round(rule_probability, 4),
            "rules_triggered": rules_triggered,
            "rule_details": rule_details,
            "total_rules_checked": 30,
            "max_possible_score": max_score
        }
        
    def calculate_threat_level(self, confidence):
            """Calculate threat level based on confidence score"""
            if confidence >= self.risk_thresholds['high']:
                return "HIGH", "🔴", "Phishing"
            elif confidence >= self.risk_thresholds['medium']:
                return "MEDIUM", "🟡", "Suspicious"
            elif confidence >= self.risk_thresholds['low']:
                return "LOW", "🟢", "Appears Safe"
            else:
                return "VERY_LOW", "⚪", "Safe"
        
    def analyze_url(self, url):
            """Complete URL analysis combining all modules and ML"""
            start_time = time.time()
            self.request_count += 1
            
            try:
                logging.info(f"🔍 Analyzing URL: {url} (Request #{self.request_count})")
                
                # Extract comprehensive features
                features, module_status, extraction_times = self.extract_comprehensive_features(url)
                
                # ML prediction
                ml_result = self.model_manager.predict(features)
                
                # Rule-based analysis
                rule_result = self.rule_based_analysis(url, features)
                
                # Combine results using configured weights
                ml_prob = ml_result.get('probability', 0)
                rule_prob = rule_result.get('rule_probability', 0)
                
                combined_prob = (ml_prob * Config.ML_WEIGHT + 
                            rule_prob * Config.HEURISTIC_WEIGHT)
                
                is_phishing = combined_prob > 0.5
                threat_level, risk_color, status_text = self.calculate_threat_level(combined_prob)
                
                # Prepare explanation
                explanation = self.generate_explanation(combined_prob, status_text, features, rule_result, url)
                
                # Organize features by category
                categorized_features = self.categorize_features(features)
                
                # Get probabilities array
                probabilities = [1 - combined_prob, combined_prob]
                
                # Prepare final result
                total_time = round(time.time() - start_time, 2)
                
                result = {
                    "url": url,
                    "timestamp": datetime.now().isoformat(),
                    "prediction": status_text,
                    "predicted_class": 0 if not is_phishing else 1,
                    "risk_score": round(combined_prob, 4),
                    "probabilities": [round(prob, 6) for prob in probabilities],
                    "explanation": explanation,
                    "features": categorized_features
                }
                
                logging.info(f"✅ Analysis complete: {status_text} (confidence: {combined_prob:.2f}, time: {total_time}s)")
                
                return result
                
            except Exception as e:
                logging.error(f"❌ Analysis error for {url}: {e}")
                return {
                    "url": url,
                    "timestamp": datetime.now().isoformat(),
                    "prediction": "Error",
                    "predicted_class": None,
                    "risk_score": 0.0,
                    "probabilities": [1.0, 0.0],
                    "explanation": [f"Analysis failed: {str(e)}"],
                    "features": {},
                    "error": f"Analysis failed: {str(e)}"
                }

    def generate_explanation(self, risk_score, prediction, features, rule_result, url):
            """Generate human-readable explanation of the analysis"""
            explanation = []
            
            # Risk score and prediction
            explanation.append(f"Risk Score: {risk_score:.2f}")
            explanation.append(f"Prediction: {prediction}")
            explanation.append("Key factors influencing prediction:")
            
            # Positive factors (safe indicators)
            positive_factors = []
            
            # SSL factors
            if features.get('ssl_has_ssl', 0) == 1:
                if features.get('ssl_ssl_cert_expired', 0) == 0:
                    positive_factors.append("Valid SSL certificate")
                else:
                    explanation.append("- Expired SSL certificate (suspicious)")
            
            # DNS factors
            if features.get('dns_has_dns_record', 0) == 1:
                positive_factors.append("DNS record exists")
            else:
                explanation.append("- No DNS record found (suspicious)")
            
            # Domain age
            domain_age = features.get('meta_domain_age_days', 0)
            if domain_age > 365:
                positive_factors.append(f"Established domain ({domain_age} days old)")
            elif domain_age > 0:
                explanation.append(f"- Relatively new domain ({domain_age} days)")
            
            # Security headers
            if features.get('header_has_x_frame_options', 0) == 1:
                positive_factors.append("Security headers present")
            else:
                explanation.append("- Missing security headers")
            
            # URL structure
            url_len = len(features.get('url_url', ''))
            if url_len < 100:
                positive_factors.append("Reasonable URL length")
            else:
                explanation.append(f"- Long URL ({url_len} characters)")
            
            # Enhanced Typosquatting findings
            typosquatting_detected = features.get('typo_typosquatting_detected', 0)
            homoglyph_detected = features.get('typo_homoglyph_detected', 0)
            targeted_domain = features.get('typo_targeted_legitimate_domain', 'none')
            
            if typosquatting_detected == 1:
                techniques = features.get('typo_techniques_used', [])
                confidence = features.get('typo_typosquatting_confidence', 0.0)
                
                if targeted_domain != 'none':
                    explanation.append(f"🚨 Typosquatting detected targeting {targeted_domain}:")
                else:
                    explanation.append("🚨 Typosquatting detected:")
                
                explanation.append(f"- Confidence: {confidence:.2f}")
                for technique in techniques[:3]:
                    explanation.append(f"- {technique}")
                
                # Special warnings for high-confidence typosquatting
                if confidence > 0.8:
                    explanation.append("⚠️  High-confidence typosquatting - exercise extreme caution")
            
            if homoglyph_detected == 1:
                homoglyph_count = features.get('typo_homoglyph_count', 0)
                homoglyph_details = features.get('typo_homoglyph_details', [])
                explanation.append(f"🔤 Homoglyph characters detected: {homoglyph_count}")
                for detail in homoglyph_details[:2]:
                    explanation.append(f"- {detail}")
            
            # Add positive factors
            for factor in positive_factors:
                explanation.append(f"✅ {factor}")
            
            # Add rule-based findings
            rules_triggered = rule_result.get('rules_triggered', [])
            if rules_triggered:
                explanation.append("Rule-based findings:")
                for rule in rules_triggered[:4]:
                    explanation.append(f"- {rule}")
            
            # Final summary based on risk level
            if risk_score < 0.3:
                explanation.append("🟢 LOW RISK: This URL appears relatively safe")
            elif risk_score < 0.7:
                explanation.append("🟡 MEDIUM RISK: Exercise caution with this URL")
            else:
                explanation.append("🔴 HIGH RISK: This URL shows strong phishing indicators")
            
            return explanation

    def categorize_features(self, features):
            """Organize features into categories"""
            categorized = {
                "model_features": {},
                "ssl_features": {},
                "dns_features": {},
                "header_features": {},
                "meta_features": {},
                "typosquatting_features": {}
            }
            
            for feature_name, value in features.items():
                if feature_name.startswith('url_'):
                    clean_name = feature_name[4:]
                    categorized["model_features"][clean_name] = value
                elif feature_name.startswith('ssl_'):
                    clean_name = feature_name[4:]
                    categorized["ssl_features"][clean_name] = value
                elif feature_name.startswith('dns_'):
                    clean_name = feature_name[4:]
                    categorized["dns_features"][clean_name] = value
                elif feature_name.startswith('header_'):
                    clean_name = feature_name[7:]
                    categorized["header_features"][clean_name] = value
                elif feature_name.startswith('meta_'):
                    clean_name = feature_name[5:]
                    categorized["meta_features"][clean_name] = value
                elif feature_name.startswith('typo_'):
                    clean_name = feature_name[5:]
                    categorized["typosquatting_features"][clean_name] = value
            
            return {k: v for k, v in categorized.items() if v}



def load_models():
    """Initialize the phishing detector - called from run.py"""
    global phishing_detector
    
    print("🎯 INITIALIZING ADVANCED PHISHING DETECTION SYSTEM")
    print(f"📁 Environment: {Config.ENVIRONMENT}")
    print(f"🔧 Debug Mode: {Config.DEBUG}")
    
    # Ensure directories exist
    ensure_directories()
    
    # Set up logging
    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO),
        format=Config.LOGGING_CONFIG['format'],
        handlers=[
            logging.FileHandler(Config.LOGGING_CONFIG['file'], encoding='utf-8'),
            logging.StreamHandler(stream=sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize the detector
        phishing_detector = AdvancedPhishingDetector()
        logger.info("✅ Models and detector loaded successfully!")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to load models: {e}")
        return False


# Flask Routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    if phishing_detector is None:
        return jsonify({
            "status": "unhealthy",
            "error": "Models not loaded",
            "timestamp": datetime.now().isoformat()
        }), 500
    
    try:
        model_health = phishing_detector.model_manager.health_check()
        
        system_health = {
            "status": "healthy",
            "version": "2.0.0",
            "environment": Config.ENVIRONMENT,
            "timestamp": datetime.now().isoformat(),
            "system": {
                "requests_processed": phishing_detector.request_count,
                "analysis_modules": phishing_detector.get_enabled_modules(),
                "cache_enabled": Config.CACHE_ENABLED,
                "cache_size": len(phishing_detector.cache)
            },
            "model": model_health,
            "configuration": {
                "ml_weight": Config.ML_WEIGHT,
                "heuristic_weight": Config.HEURISTIC_WEIGHT,
                "risk_thresholds": Config.RISK_THRESHOLDS
            }
        }
        
        return jsonify(system_health)
    
    except Exception as e:
        return jsonify({
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/analyze', methods=['POST'])
def analyze_url_endpoint():
    global phishing_detector
    if phishing_detector is None:
        if not load_models():
            return jsonify({"error": "Models failed to load"}), 503
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({"error": "Empty URL provided"}), 400
        
        if len(url) > 2048:
            return jsonify({"error": "URL too long (max 2048 characters)"}), 400
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return jsonify({"error": "Invalid URL format - no domain found"}), 400
        except Exception as e:
            return jsonify({"error": f"Invalid URL format: {str(e)}"}), 400
        
        cache_key = f"analysis:{url}"
        if Config.CACHE_ENABLED and cache_key in phishing_detector.cache:
            cached_result = phishing_detector.cache[cache_key]
            if time.time() - cached_result['cache_timestamp'] < Config.CACHE_TIMEOUT:
                cached_result['cached'] = True
                return jsonify(cached_result)
        
        result = phishing_detector.analyze_url(url)
        
        if Config.CACHE_ENABLED:
            result['cache_timestamp'] = time.time()
            phishing_detector.cache[cache_key] = result
            if len(phishing_detector.cache) > Config.CACHE_MAX_SIZE:
                oldest_key = min(phishing_detector.cache.keys(), 
                               key=lambda k: phishing_detector.cache[k]['cache_timestamp'])
                del phishing_detector.cache[oldest_key]
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Request processing error: {e}")
        return jsonify({
            "error": "Invalid request format",
            "details": str(e),
            "timestamp": datetime.now().isoformat()
        }), 400

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def handle_exception(error):
    logging.error(f"Unhandled exception: {error}")
    return jsonify({
        "error": "An unexpected error occurred",
        "details": str(error) if Config.DEBUG else "Contact administrator"
    }), 500

# Make load_models available for import
# Add this after all your code, before the if __name__ block
def create_app():
    """Create Flask application for WSGI servers"""
    if load_models():
        return app
    else:
        raise RuntimeError("Failed to load models")

# For WSGI servers like gunicorn
application = create_app()

if __name__ == "__main__":
    if load_models():
        print(f"🚀 Starting server on {Config.HOST}:{Config.PORT}")
        app.run(
            host=Config.HOST,
            port=Config.PORT,
            debug=Config.DEBUG,
            threaded=True
        )
    else:
        print("❌ Failed to load models - cannot start server")
        