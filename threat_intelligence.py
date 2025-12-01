# threat_intelligence.py
import vt
import requests
import json
from datetime import datetime, timedelta
import redis

class ThreatIntelligence:
    def __init__(self):
        # API ключи (должны храниться в защищенном хранилище)
        self.vt_api_key = "YOUR_VIRUSTOTAL_API_KEY"
        self.abuseipdb_key = "YOUR_ABUSEIPDB_API_KEY"
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        
        # Кэшированные данные угроз
        self.threat_feeds = {
            'alienvault': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
            'emerging_threats': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            'blocklist_de': 'https://lists.blocklist.de/lists/all.txt'
        }
        
        self.load_threat_feeds()
    
    def load_threat_feeds(self):
        """Загрузка актуальных списков угроз"""
        for feed_name, feed_url in self.threat_feeds.items():
            try:
                response = requests.get(feed_url, timeout=10)
                if response.status_code == 200:
                    # Кэширование на 1 час
                    self.redis_client.setex(
                        f'threat_feed:{feed_name}',
                        3600,
                        response.text
                    )
            except Exception as e:
                print(f"Error loading threat feed {feed_name}: {e}")
    
    def check_ip(self, ip_address):
        """Проверка IP через все источники"""
        results = {
            'ip': ip_address,
            'risk_score': 0,
            'threats': [],
            'sources': []
        }
        
        # Проверка VirusTotal
        vt_result = self.check_virustotal(ip_address)
        if vt_result:
            results['threats'].extend(vt_result.get('detected_urls', []))
            results['risk_score'] += vt_result.get('positives', 0) * 10
        
        # Проверка AbuseIPDB
        abuse_result = self.check_abuseipdb(ip_address)
        if abuse_result:
            results['threats'].extend(abuse_result.get('reports', []))
            results['risk_score'] += abuse_result.get('abuseConfidenceScore', 0)
        
        # Проверка локальных списков
        for feed_name in self.threat_feeds.keys():
            feed_data = self.redis_client.get(f'threat_feed:{feed_name}')
            if feed_data and ip_address in feed_data.decode():
                results['threats'].append(f'Найден в {feed_name}')
                results['risk_score'] += 20
        
        # Классификация риска
        if results['risk_score'] > 80:
            results['risk_level'] = 'critical'
        elif results['risk_score'] > 50:
            results['risk_level'] = 'high'
        elif results['risk_score'] > 20:
            results['risk_level'] = 'medium'
        else:
            results['risk_level'] = 'low'
        
        return results
    
    def check_virustotal(self, ip_address):
        """Проверка через VirusTotal API"""
        try:
            client = vt.Client(self.vt_api_key)
            url_id = vt.url_id(ip_address)
            analysis = client.get_object(f"/urls/{url_id}")
            
            return {
                'positives': analysis.last_analysis_stats['malicious'],
                'total': sum(analysis.last_analysis_stats.values()),
                'detected_urls': [
                    scan for scan in analysis.last_analysis_results.values()
                    if scan['category'] == 'malicious'
                ]
            }
        except Exception as e:
            print(f"VirusTotal error: {e}")
            return None
    
    def check_abuseipdb(self, ip_address):
        """Проверка через AbuseIPDB"""
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                return response.json().get('data', {})
        except Exception as e:
            print(f"AbuseIPDB error: {e}")
        
        return None
    
    def get_ioc_feed(self):
        """Получение свежих индикаторов компрометации"""
        iocs = []
        
        # MITRE ATT&CK техники
        mitre_techniques = [
            'T1059',  # Command and Scripting Interpreter
            'T1068',  # Exploitation for Privilege Escalation
            'T1071',  # Application Layer Protocol
            'T1105',  # Ingress Tool Transfer
            'T1204',  # User Execution
        ]
        
        # YARA правила для обнаружения
        yara_rules = """
        rule ransomware_indicator {
            strings:
                $s1 = "WannaCry" nocase
                $s2 = "NotPetya" nocase
                $s3 = "Locky" nocase
            condition:
                any of them
        }
        
        rule c2_beacon {
            strings:
                $http = "POST /beacon HTTP/1.1"
                $https = "CONNECT" nocase
            condition:
                any of them
        }
        """
        
        return {
            'mitre_techniques': mitre_techniques,
            'yara_rules': yara_rules,
            'update_time': datetime.now().isoformat()
        }