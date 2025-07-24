"""
Base generator class for cybersecurity data generation
"""
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json
import ipaddress
from faker import Faker
from faker.providers import internet, person, company, date_time

class BaseSecurityGenerator:
    """Base class for generating realistic cybersecurity data"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the generator with configuration"""
        self.config = config
        self.fake = Faker()
        
        # Add additional providers
        self.fake.add_provider(internet)
        self.fake.add_provider(person)
        self.fake.add_provider(company)
        self.fake.add_provider(date_time)
        
        # Cache for consistent data generation
        self._user_cache = {}
        self._asset_cache = {}
        self._ip_cache = {}
        
        # Load threat intelligence indicators
        self._threat_indicators = self._load_threat_indicators()
        
    def generate_log_id(self) -> str:
        """Generate unique log ID"""
        return str(uuid.uuid4())
    
    def generate_timestamp(self, 
                          start_date: datetime, 
                          end_date: datetime,
                          business_hours_bias: float = 0.7) -> datetime:
        """Generate realistic timestamp with business hours bias"""
        
        # Random base time
        total_seconds = int((end_date - start_date).total_seconds())
        random_seconds = random.randint(0, total_seconds)
        timestamp = start_date + timedelta(seconds=random_seconds)
        
        # Apply business hours bias
        if random.random() < business_hours_bias:
            # Force to business hours (9 AM - 6 PM weekdays)
            timestamp = timestamp.replace(
                hour=random.randint(9, 17),
                minute=random.randint(0, 59),
                second=random.randint(0, 59)
            )
            
            # Avoid weekends for business hours
            while timestamp.weekday() >= 5:  # Saturday = 5, Sunday = 6
                timestamp += timedelta(days=1)
                
        return timestamp
    
    def generate_internal_ip(self, location: str = 'headquarters') -> str:
        """Generate internal IP address based on location"""
        if location in self._ip_cache:
            return random.choice(self._ip_cache[location])
            
        # Generate IP range for location
        office_config = self.config.get('OFFICE_LOCATIONS', {}).get(location, {})
        ip_range = office_config.get('ip_range', '10.1.0.0/16')
        
        network = ipaddress.IPv4Network(ip_range)
        ips = [str(ip) for ip in network.hosts()][:1000]  # Limit to 1000 IPs
        self._ip_cache[location] = ips
        
        return random.choice(ips)
    
    def generate_external_ip(self, malicious: bool = False) -> str:
        """Generate external IP address, optionally malicious"""
        if malicious:
            # Return known bad IP from threat intel
            threat_ips = [indicator['indicator'] for indicator in self._threat_indicators 
                         if indicator['type'] == 'ip']
            if threat_ips:
                return random.choice(threat_ips)
        
        # Generate random external IP (avoid RFC 1918 ranges)
        while True:
            ip = self.fake.ipv4()
            ip_obj = ipaddress.IPv4Address(ip)
            
            # Skip private ranges
            if not ip_obj.is_private and not ip_obj.is_loopback:
                return ip
    
    def generate_user_id(self, department: Optional[str] = None) -> Dict[str, str]:
        """Generate consistent user information"""
        
        # Use cached user if available
        cache_key = f"{department or 'any'}"
        if cache_key in self._user_cache:
            return random.choice(self._user_cache[cache_key])
        
        # Generate new users for department
        users = []
        departments = [department] if department else self.config.get('DEPARTMENTS', [])
        
        for dept in departments:
            roles = self.config.get('USER_ROLES', {}).get(dept, ['Employee'])
            user_count = random.randint(20, 50)  # 20-50 users per department
            
            for _ in range(user_count):
                first_name = self.fake.first_name()
                last_name = self.fake.last_name()
                username = f"{first_name[0].lower()}{last_name.lower()}"
                
                user = {
                    'user_id': username,
                    'username': username,
                    'email': f"{username}@company.com",
                    'first_name': first_name,
                    'last_name': last_name,
                    'department': dept,
                    'title': random.choice(roles),
                    'employee_type': random.choices(
                        ['full_time', 'contractor', 'temp'],
                        weights=[0.8, 0.15, 0.05]
                    )[0],
                    'security_clearance': random.choices(
                        self.config.get('SECURITY_CLEARANCES', ['none']),
                        weights=[0.7, 0.2, 0.08, 0.02]
                    )[0],
                    'location': random.choices(
                        list(self.config.get('OFFICE_LOCATIONS', {}).keys()),
                        weights=[0.4, 0.3, 0.2, 0.1]
                    )[0]
                }
                users.append(user)
        
        self._user_cache[cache_key] = users
        return random.choice(users)
    
    def generate_hostname(self, asset_type: str = 'workstation') -> Dict[str, str]:
        """Generate consistent asset information"""
        
        cache_key = asset_type
        if cache_key not in self._asset_cache:
            self._asset_cache[cache_key] = []
        
        if self._asset_cache[cache_key]:
            return random.choice(self._asset_cache[cache_key])
        
        # Generate new assets
        assets = []
        asset_count = {
            'workstation': 800,
            'server': 100,
            'mobile': 300,
            'iot': 50
        }.get(asset_type, 100)
        
        for i in range(asset_count):
            if asset_type == 'workstation':
                hostname = f"WKS-{random.choice(['SF', 'NY', 'LON', 'SG'])}-{i+1:04d}"
                os = random.choice([
                    'Windows 10', 'Windows 11', 'macOS Monterey', 'macOS Ventura', 'Ubuntu 20.04'
                ])
            elif asset_type == 'server':
                service = random.choice(['web', 'db', 'app', 'mail', 'file', 'dns'])
                hostname = f"{service}-server-{i+1:02d}"
                os = random.choice(['Ubuntu 20.04', 'CentOS 7', 'Windows Server 2019', 'RHEL 8'])
            else:
                hostname = f"{asset_type}-{i+1:04d}"
                os = random.choice(['iOS 15', 'Android 12', 'Linux', 'Embedded'])
            
            asset = {
                'asset_id': hostname,
                'hostname': hostname,
                'asset_type': asset_type,
                'operating_system': os,
                'location': random.choice(list(self.config.get('OFFICE_LOCATIONS', {}).keys())),
                'criticality': random.choices(
                    ['low', 'medium', 'high', 'critical'],
                    weights=[0.4, 0.4, 0.15, 0.05]
                )[0],
                'owner': self.generate_user_id()['user_id']
            }
            assets.append(asset)
        
        self._asset_cache[cache_key] = assets
        return random.choice(assets)
    
    def generate_geolocation(self, location_type: str = 'office') -> Dict[str, Any]:
        """Generate geolocation data"""
        
        if location_type == 'office':
            location = random.choice(list(self.config.get('OFFICE_LOCATIONS', {}).values()))
            return {
                'city': location['city'],
                'country': location['country'],
                'latitude': self.fake.latitude(),
                'longitude': self.fake.longitude(),
                'timezone': location['timezone']
            }
        elif location_type == 'threat':
            location = random.choice(self.config.get('THREAT_LOCATIONS', []))
            return {
                'city': location['city'],
                'country': location['country'],
                'latitude': self.fake.latitude(),
                'longitude': self.fake.longitude(),
                'threat_level': location['threat_level']
            }
        else:  # random location
            return {
                'city': self.fake.city(),
                'country': self.fake.country(),
                'latitude': self.fake.latitude(),
                'longitude': self.fake.longitude()
            }
    
    def generate_user_agent(self, device_type: str = 'desktop') -> str:
        """Generate realistic user agent string"""
        
        if device_type == 'desktop':
            browsers = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/91.0.4472.124',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/14.1.1'
            ]
        elif device_type == 'mobile':
            browsers = [
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1',
                'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0',
                'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome/91.0.4472.120'
            ]
        else:  # suspicious/bot
            browsers = [
                'curl/7.68.0',
                'python-requests/2.25.1',
                'Wget/1.20.3 (linux-gnu)',
                'sqlmap/1.5.7#stable'
            ]
            
        return random.choice(browsers)
    
    def _load_threat_indicators(self) -> List[Dict[str, Any]]:
        """Load threat intelligence indicators"""
        
        # This would normally load from external threat feeds
        # For demo purposes, we'll generate some realistic indicators
        indicators = []
        
        # Malicious IPs
        malicious_ips = [
            '45.133.203.192', '185.220.101.32', '198.98.51.189',
            '103.253.27.108', '94.102.61.38', '178.128.83.165'
        ]
        
        for ip in malicious_ips:
            indicators.append({
                'indicator': ip,
                'type': 'ip',
                'threat_type': random.choice(['malware', 'c2', 'scanning', 'botnet']),
                'confidence': random.uniform(0.7, 0.95),
                'source': random.choice(self.config.get('THREAT_INTEL_SOURCES', ['internal']))
            })
        
        # Malicious domains
        malicious_domains = [
            'evil-cdn.net', 'malware-host.com', 'phishing-site.org',
            'c2-server.info', 'bad-actor.biz', 'threat-domain.xyz'
        ]
        
        for domain in malicious_domains:
            indicators.append({
                'indicator': domain,
                'type': 'domain',
                'threat_type': random.choice(['phishing', 'c2', 'malware']),
                'confidence': random.uniform(0.8, 0.98),
                'source': random.choice(self.config.get('THREAT_INTEL_SOURCES', ['internal']))
            })
        
        # Malicious file hashes
        for _ in range(50):
            indicators.append({
                'indicator': self.fake.sha256(),
                'type': 'hash',
                'threat_type': random.choice(['malware', 'ransomware', 'trojan']),
                'confidence': random.uniform(0.85, 0.99),
                'source': random.choice(self.config.get('THREAT_INTEL_SOURCES', ['internal']))
            })
        
        return indicators
    
    def inject_threat_scenario(self, 
                             event: Dict[str, Any], 
                             scenario: str, 
                             current_time: datetime) -> Dict[str, Any]:
        """Inject threat scenario indicators into normal event"""
        
        scenario_config = self.config.get('THREAT_SCENARIOS', {}).get(scenario)
        if not scenario_config:
            return event
        
        # Determine scenario phase based on time
        scenario_start = current_time - timedelta(days=scenario_config.get('duration_days', 30))
        days_elapsed = (current_time - scenario_start).days
        
        current_phase = None
        for phase_info in scenario_config.get('timeline', []):
            if days_elapsed >= phase_info['day']:
                current_phase = phase_info
        
        if not current_phase:
            return event
        
        # Apply scenario-specific modifications
        if scenario == 'phantom_exfiltrator':
            if current_phase['phase'] == 'exfiltration':
                # Large data transfers
                if 'bytes_transferred' in event:
                    event['bytes_transferred'] = random.randint(50_000_000, 500_000_000)  # 50-500MB
                
                # Unusual destination
                event['destination_ip'] = self.generate_external_ip(malicious=True)
                event['threat_score'] = random.uniform(0.7, 0.9)
        
        elif scenario == 'insider_threat':
            # After hours access
            if event.get('event_time'):
                event['event_time'] = event['event_time'].replace(
                    hour=random.randint(20, 23),  # 8 PM - 11 PM
                    minute=random.randint(0, 59)
                )
            
            # Access unusual files
            if 'file_path' in event:
                sensitive_files = [
                    '/home/shared/financial_data.xlsx',
                    '/home/shared/customer_database.sql',
                    '/home/shared/employee_records.csv'
                ]
                event['file_path'] = random.choice(sensitive_files)
        
        return event 