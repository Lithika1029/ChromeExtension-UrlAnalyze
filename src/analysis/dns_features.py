import urllib.parse
import time
import re
import dns.resolver

def extract_dns_features_advanced(url):
    """Advanced DNS features using dnspython library - FIXED & IMPROVED"""
    features = {
        'dns_record_count': 0,
        'has_dns_record': 0,
        'ip_reputation': 0,          # Placeholder (can be extended with external APIs)
        'dns_response_time': None,
        'has_multiple_ips': 0,
        'ttl_value': None,
        'ip_address': None,
        'is_ipv6': 0,
        'mx_record_count': 0,
        'ns_record_count': 0,
    }
    
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Handle localhost/IPs directly
        if (domain in ['localhost', '127.0.0.1', '::1'] or 
            re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) or
            re.match(r'^\[[0-9a-fA-F:]+\]$', domain)):
            features['ip_address'] = domain
            features['has_dns_record'] = 1
            return features
        
        # DNS lookup start
        start_time = time.time()
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            features['dns_response_time'] = round(time.time() - start_time, 4)
            features['has_dns_record'] = 1
            features['dns_record_count'] = len(a_records)
            features['has_multiple_ips'] = 1 if len(a_records) > 1 else 0
            
            if a_records:
                features['ip_address'] = str(a_records[0])
                features['ttl_value'] = a_records.rrset.ttl if a_records.rrset else None
            
            # AAAA (IPv6)
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA', lifetime=2)
                features['is_ipv6'] = 1 if len(aaaa_records) > 0 else 0
            except:
                features['is_ipv6'] = 0
                
            # MX Records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX', lifetime=2)
                features['mx_record_count'] = len(mx_records)
            except:
                features['mx_record_count'] = 0
                
            # NS Records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS', lifetime=2)
                features['ns_record_count'] = len(ns_records)
            except:
                features['ns_record_count'] = 0
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            features['has_dns_record'] = 0
        except Exception as e:
            print(f"DNS error for {domain}: {e}")
            features['has_dns_record'] = 0
            
    except Exception as e:
        print(f"General error in DNS extraction: {e}")
    
    return features
