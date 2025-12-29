import urllib.parse
import re
import ssl
import socket
from datetime import datetime

class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'update', 'secure', 'banking',
            'confirm', 'suspend', 'urgent', 'click', 'free', 'bonus',
            'winner', 'prize', 'gift', 'offer'
        ]
    
    def extract_features(self, url):
        """Extract features from URL for ML model"""
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        
        features = {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'domain_length': len(domain),
            'subdomain_count': domain.count('.') - 1 if '.' in domain else 0,
            'has_https': 1 if parsed_url.scheme == 'https' else 0,
            'has_ip': 1 if self._is_ip_address(domain) else 0,
            'suspicious_keywords': self._count_suspicious_keywords(url.lower())
        }
        
        return features
    
    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(ip_pattern.match(domain))
    
    def _count_suspicious_keywords(self, url):
        """Count suspicious keywords in URL"""
        count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url:
                count += 1
        return count
    
    def check_ssl_certificate(self, url):
        """Advanced SSL Certificate Validation"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Skip if not HTTPS
            if parsed_url.scheme != 'https':
                return {
                    'has_ssl': False,
                    'ssl_valid': False,
                    'message': 'No SSL certificate (HTTP connection)',
                    'risk_level': 'High'
                }
            
            print(f"🔒 Checking SSL certificate for: {domain}")
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate information
                    ssl_info = self._parse_ssl_certificate(cert, domain)
                    print(f"✅ SSL certificate validated successfully")
                    return ssl_info
                    
        except ssl.SSLCertVerificationError as e:
            print(f"❌ SSL Certificate verification failed: {str(e)}")
            return {
                'has_ssl': True,
                'ssl_valid': False,
                'message': 'Invalid SSL certificate',
                'error': str(e),
                'risk_level': 'High'
            }
        except socket.timeout:
            print(f"⚠️ SSL check timeout for {domain}")
            return {
                'has_ssl': False,
                'ssl_valid': False,
                'message': 'Connection timeout',
                'risk_level': 'Unknown'
            }
        except Exception as e:
            print(f"⚠️ SSL check error: {str(e)}")
            return {
                'has_ssl': False,
                'ssl_valid': False,
                'message': f'SSL check failed: {str(e)}',
                'risk_level': 'Unknown'
            }
    
    def _parse_ssl_certificate(self, cert, domain):
        """Parse SSL certificate details"""
        try:
            # Get expiry date
            not_after = cert.get('notAfter')
            not_before = cert.get('notBefore')
            
            # Convert to datetime
            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            issue_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
            
            # Calculate days until expiry
            days_until_expiry = (expiry_date - datetime.now()).days
            
            # Get issuer information
            issuer = dict(x[0] for x in cert.get('issuer', ()))
            issuer_org = issuer.get('organizationName', 'Unknown')
            
            # Get subject information
            subject = dict(x[0] for x in cert.get('subject', ()))
            common_name = subject.get('commonName', domain)
            
            # Determine SSL status
            if days_until_expiry < 0:
                ssl_status = 'Expired'
                risk_level = 'High'
                validity_message = f'Certificate expired {abs(days_until_expiry)} days ago'
            elif days_until_expiry < 30:
                ssl_status = 'Expiring Soon'
                risk_level = 'Medium'
                validity_message = f'Certificate expires in {days_until_expiry} days'
            else:
                ssl_status = 'Valid'
                risk_level = 'Low'
                validity_message = f'Certificate valid for {days_until_expiry} days'
            
            return {
                'has_ssl': True,
                'ssl_valid': days_until_expiry > 0,
                'ssl_status': ssl_status,
                'issuer': issuer_org,
                'common_name': common_name,
                'issue_date': issue_date.strftime('%Y-%m-%d'),
                'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                'days_until_expiry': days_until_expiry,
                'validity_message': validity_message,
                'risk_level': risk_level,
                'message': f'Valid SSL certificate from {issuer_org}'
            }
            
        except Exception as e:
            print(f"❌ Error parsing certificate: {str(e)}")
            return {
                'has_ssl': True,
                'ssl_valid': False,
                'message': f'Error parsing certificate: {str(e)}',
                'risk_level': 'Unknown'
            }
    
    def get_domain_info(self, url):
        """Get domain age and registration information"""
        try:
            import whois
            
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            # Remove www. if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            print(f"🌐 Fetching domain info for: {domain}")
            
            # Get WHOIS information
            domain_info = whois.whois(domain)
            
            # Extract creation date
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # Calculate domain age
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                age_years = age_days / 365.25
                
                return {
                    'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else 'Unknown',
                    'age_days': age_days,
                    'age_years': round(age_years, 2),
                    'registrar': domain_info.registrar if hasattr(domain_info, 'registrar') else 'Unknown',
                    'status': 'Active'
                }
            
            return None
            
        except Exception as e:
            print(f"⚠️ Domain info error: {str(e)}")
            return None
