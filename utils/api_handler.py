import requests
import os
from dotenv import load_dotenv
import time
from base64 import urlsafe_b64encode

load_dotenv()

class VirusTotalAPI:
    def __init__(self):
        self.api_key = "0a22330ca03e77cffe604274ec5bc5f11e434ffc11304e766f07be87b7553a2d"
        self.base_url = 'https://www.virustotal.com/api/v3/'
        self.headers = {
            'x-apikey': self.api_key,
            'Content-Type': 'application/json'
        }
        
    def scan_url(self, url):
        """Scan URL using VirusTotal API v3"""
        try:
            print(f"Scanning URL with VirusTotal: {url}")
            
            # Step 1: Submit URL for scanning
            scan_data = {'url': url}
            scan_response = requests.post(
                f'{self.base_url}urls',
                headers=self.headers,
                json=scan_data
            )
            
            if scan_response.status_code == 200:
                scan_result = scan_response.json()
                analysis_id = scan_result['data']['id']
                
                # Step 2: Wait and get the analysis result
                time.sleep(10)  # Wait for analysis to complete
                return self.get_analysis_result(analysis_id)
            
            print(f"Failed to submit URL for scanning: {scan_response.status_code}")
            return None
            
        except Exception as e:
            print(f"VirusTotal scan error: {str(e)}")
            return None
    
    def get_analysis_result(self, analysis_id):
        """Get analysis result by ID"""
        try:
            analysis_response = requests.get(
                f'{self.base_url}analyses/{analysis_id}',
                headers=self.headers
            )
            
            if analysis_response.status_code == 200:
                return analysis_response.json()
            
            return None
            
        except Exception as e:
            print(f"Error getting analysis result: {str(e)}")
            return None
    
    def get_url_report(self, url):
        """Get existing report for URL using VirusTotal API v3"""
        try:
            # Encode URL in base64 format as required by API v3
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            
            response = requests.get(
                f'{self.base_url}urls/{url_id}',
                headers=self.headers
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Extract scan statistics
                stats = result['data']['attributes'].get('last_analysis_stats', {})
                
                return {
                    'response_code': 1,
                    'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                    'total': sum(stats.values()),
                    'scan_date': result['data']['attributes'].get('last_analysis_date', ''),
                    'permalink': f"https://www.virustotal.com/gui/url/{url_id}",
                    'stats': stats
                }
            
            return None
            
        except Exception as e:
            print(f"Error getting URL report: {str(e)}")
            return None

    def check_domain(self, domain):
        """Check domain reputation"""
        try:
            response = requests.get(
                f'{self.base_url}domains/{domain}',
                headers=self.headers
            )
            
            if response.status_code == 200:
                result = response.json()
                stats = result['data']['attributes'].get('last_analysis_stats', {})
                
                return {
                    'domain': domain,
                    'reputation': result['data']['attributes'].get('reputation', 0),
                    'stats': stats,
                    'categories': result['data']['attributes'].get('categories', {})
                }
            
            return None
            
        except Exception as e:
            print(f"Error checking domain: {str(e)}")
            return None
