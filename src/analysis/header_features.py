import requests
import urllib.parse
import warnings
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
import time

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def create_session():
    """Create a robust requests session with retry logic"""
    session = requests.Session()
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]
    )
    
    session = requests.Session()
    retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])

    adapter = HTTPAdapter(max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })
    
    return session

def extract_header_features(url):
    """Extract features from HTTP headers"""
    features = {
        'has_x_powered_by': 0,
        'has_server_header': 0,
        'has_x_frame_options': 0,
        'has_strict_transport_security': 0,
        'has_content_security_policy': 0,
        'has_x_content_type_options': 0,
        'content_type_length': 0,
        'server_length': 0,
        'content_type': None,
        'server': None,
        'redirect_count': 0,
        'content_length_bytes': None,
        'final_url': url,
        'status_code': 0,
        'status_message': "Unknown",
        'response_time': 0,
    }
    
    session = None
    try:
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme.startswith('http'):
            return features
        
        session = create_session()
        start_time = time.time()
        
        response = session.get(
            url, 
            timeout=(3, 10), 
            allow_redirects=True,
            stream=True
        )
        
        features['response_time'] = round(time.time() - start_time, 4)
        features['final_url'] = response.url
        features['status_code'] = response.status_code
        features['redirect_count'] = len(response.history)
        features['status_message'] = "OK" if 200 <= response.status_code < 400 else "Error"
        
        headers = response.headers
        header_keys = [key.lower() for key in headers.keys()]
        
        features.update({
            'has_x_powered_by': 1 if 'x-powered-by' in header_keys else 0,
            'has_server_header': 1 if 'server' in header_keys else 0,
            'has_x_frame_options': 1 if 'x-frame-options' in header_keys else 0,
            'has_strict_transport_security': 1 if 'strict-transport-security' in header_keys else 0,
            'has_content_security_policy': 1 if 'content-security-policy' in header_keys else 0,
            'has_x_content_type_options': 1 if 'x-content-type-options' in header_keys else 0,
            'content_type_length': len(headers.get('Content-Type', '')),
            'server_length': len(headers.get('Server', '')),
            'content_type': headers.get('Content-Type'),
            'server': headers.get('Server'),
            'content_length_bytes': headers.get('Content-Length'),
        })
        
        response.close()
        
    except requests.exceptions.SSLError:
        features.update({'status_code': -1, 'status_message': "SSL Error"})
    except requests.exceptions.ConnectionError:
        features.update({'status_code': -2, 'status_message': "Connection Error"})
    except requests.exceptions.Timeout:
        features.update({'status_code': -3, 'status_message': "Timeout"})
    except requests.exceptions.TooManyRedirects:
        features.update({'status_code': -4, 'status_message': "Too Many Redirects"})
    except requests.exceptions.RequestException as e:
        features.update({'status_code': -5, 'status_message': f"Request Error: {e}"})
    except Exception as e:
        features.update({'status_code': -6, 'status_message': f"Unexpected Error: {e}"})
    finally:
        if session:
            session.close()
    
    return features
