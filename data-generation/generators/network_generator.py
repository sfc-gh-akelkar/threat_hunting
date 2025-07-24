"""
Network traffic log generator for cybersecurity demo
"""
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
from base_generator import BaseSecurityGenerator

class NetworkLogGenerator(BaseSecurityGenerator):
    """Generate realistic network traffic logs"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Common ports and protocols
        self.common_ports = {
            'tcp': [80, 443, 22, 23, 21, 25, 53, 110, 143, 993, 995, 465, 587, 3389, 5432, 3306],
            'udp': [53, 67, 68, 69, 123, 161, 162, 514, 1812, 1813]
        }
        
        # Application protocols
        self.app_protocols = [
            'HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 'DNS', 'IMAP', 'POP3', 
            'SMB', 'RDP', 'LDAP', 'SNMP', 'DHCP', 'NTP'
        ]
        
        # Response codes for web traffic
        self.response_codes = [200, 301, 302, 404, 403, 500, 502, 503]
        
    def generate_event(self, 
                      timestamp: datetime, 
                      scenario: str = None,
                      threat_probability: float = 0.05) -> Dict[str, Any]:
        """Generate a single network log event"""
        
        # Determine if this should be a threat event
        is_threat = random.random() < threat_probability
        
        # Select user and location
        user = self.generate_user_id()
        location = user['location']
        
        # Generate basic network event
        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
        
        if protocol in ['TCP', 'UDP']:
            source_port = random.randint(1024, 65535)
            
            if protocol == 'TCP':
                dest_port = random.choice(self.common_ports['tcp'])
            else:
                dest_port = random.choice(self.common_ports['udp'])
        else:
            source_port = None
            dest_port = None
        
        # Generate IPs
        source_ip = self.generate_internal_ip(location)
        
        if is_threat:
            destination_ip = self.generate_external_ip(malicious=True)
            threat_score = random.uniform(0.6, 0.9)
        else:
            # Mix of internal and external destinations
            if random.random() < 0.3:
                destination_ip = self.generate_internal_ip(location)
            else:
                destination_ip = self.generate_external_ip(malicious=False)
            threat_score = random.uniform(0.0, 0.3)
        
        # Generate traffic volume
        if is_threat and scenario == 'phantom_exfiltrator':
            # Large data exfiltration
            bytes_sent = random.randint(10_000_000, 100_000_000)  # 10-100MB
            bytes_received = random.randint(1000, 10000)
        else:
            # Normal traffic patterns
            bytes_sent = random.randint(100, 50000)
            bytes_received = random.randint(100, 500000)
        
        # Connection duration
        duration_ms = random.randint(100, 30000)
        
        # Connection state
        connection_states = ['ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 
                           'FIN_WAIT2', 'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'LISTEN']
        connection_state = random.choice(connection_states)
        
        # Application protocol
        app_protocol = self._determine_app_protocol(dest_port)
        
        # Generate hostnames
        source_hostname = f"{user['user_id']}-{random.choice(['laptop', 'desktop', 'mobile'])}"
        
        if destination_ip.startswith('10.'):
            # Internal destination
            dest_services = ['file-server', 'db-server', 'web-server', 'mail-server', 'dns-server']
            destination_hostname = f"{random.choice(dest_services)}-{random.randint(1, 10):02d}"
            destination_domain = 'company.local'
        else:
            # External destination
            if is_threat:
                threat_domains = ['evil-cdn.net', 'malware-host.com', 'c2-server.info']
                destination_domain = random.choice(threat_domains)
            else:
                legitimate_domains = ['github.com', 'stackoverflow.com', 'aws.amazon.com', 
                                    'google.com', 'microsoft.com', 'slack.com']
                destination_domain = random.choice(legitimate_domains)
            destination_hostname = destination_domain
        
        # User agent (for web traffic)
        user_agent = None
        if dest_port in [80, 443]:
            user_agent = self.generate_user_agent('suspicious' if is_threat else 'desktop')
        
        # Response code (for web traffic)
        response_code = None
        if dest_port in [80, 443]:
            if is_threat:
                response_code = random.choice([200, 404, 403])  # Threats often get 200 or blocked
            else:
                response_code = random.choices(
                    [200, 301, 302, 404, 403, 500], 
                    weights=[0.7, 0.1, 0.1, 0.05, 0.03, 0.02]
                )[0]
        
        # Geolocation
        if destination_ip.startswith('10.'):
            geolocation = self.generate_geolocation('office')
        elif is_threat:
            geolocation = self.generate_geolocation('threat')
        else:
            geolocation = self.generate_geolocation('random')
        
        # Build the log event
        event = {
            'log_id': self.generate_log_id(),
            'event_time': timestamp,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'source_port': source_port,
            'destination_port': dest_port,
            'protocol': protocol,
            'bytes_sent': bytes_sent,
            'bytes_received': bytes_received,
            'duration_ms': duration_ms,
            'connection_state': connection_state,
            'user_id': user['user_id'],
            'session_id': self.generate_log_id()[:8],
            'source_hostname': source_hostname,
            'destination_hostname': destination_hostname,
            'destination_domain': destination_domain,
            'application_protocol': app_protocol,
            'user_agent': user_agent,
            'response_code': response_code,
            'threat_score': threat_score,
            'geolocation': geolocation,
            'raw_log': self._generate_raw_log(protocol, source_ip, destination_ip, dest_port)
        }
        
        # Apply threat scenario modifications
        if scenario:
            event = self.inject_threat_scenario(event, scenario, timestamp)
        
        return event
    
    def _determine_app_protocol(self, port: int) -> str:
        """Determine application protocol based on port"""
        port_mapping = {
            80: 'HTTP',
            443: 'HTTPS', 
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'SQL Server',
            139: 'NetBIOS',
            445: 'SMB',
            389: 'LDAP',
            636: 'LDAPS',
            161: 'SNMP',
            162: 'SNMP-TRAP'
        }
        
        return port_mapping.get(port, 'Unknown')
    
    def _generate_raw_log(self, protocol: str, source_ip: str, dest_ip: str, dest_port: int) -> Dict[str, Any]:
        """Generate raw log data in a realistic format"""
        
        if protocol == 'TCP' and dest_port in [80, 443]:
            # HTTP/HTTPS log
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            paths = ['/api/users', '/login', '/dashboard', '/admin', '/config', '/data']
            
            return {
                'timestamp': datetime.now().isoformat(),
                'method': random.choice(methods),
                'path': random.choice(paths),
                'status': random.choice([200, 404, 403, 500]),
                'user_agent': self.generate_user_agent(),
                'size': random.randint(500, 50000)
            }
        else:
            # Generic network log
            return {
                'timestamp': datetime.now().isoformat(),
                'src': source_ip,
                'dst': dest_ip,
                'proto': protocol,
                'dport': dest_port,
                'flags': random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH']),
                'len': random.randint(64, 1500)
            }
    
    def generate_scenario_events(self, 
                                scenario: str, 
                                start_time: datetime, 
                                end_time: datetime, 
                                event_count: int) -> List[Dict[str, Any]]:
        """Generate events for a specific threat scenario"""
        
        events = []
        scenario_config = self.config.get('THREAT_SCENARIOS', {}).get(scenario)
        
        if not scenario_config:
            return events
        
        # Get target users for the scenario
        target_users = scenario_config.get('target_users', [])
        
        for i in range(event_count):
            # Generate timestamp
            timestamp = self.generate_timestamp(start_time, end_time, business_hours_bias=0.3)
            
            # Higher probability of threat events for target users
            if target_users and random.random() < 0.8:
                # Force specific user for scenario
                user = {
                    'user_id': random.choice(target_users),
                    'location': 'headquarters'  # Assume primary location
                }
                self._user_cache['scenario'] = [user]
                event = self.generate_event(timestamp, scenario, threat_probability=0.8)
            else:
                event = self.generate_event(timestamp, scenario, threat_probability=0.1)
            
            events.append(event)
        
        return events
    
    def generate_bulk_events(self, 
                           start_time: datetime, 
                           end_time: datetime, 
                           events_per_day: int,
                           scenarios: List[str] = None) -> List[Dict[str, Any]]:
        """Generate bulk network events with optional threat scenarios"""
        
        total_days = (end_time - start_time).days
        total_events = events_per_day * total_days
        
        events = []
        scenario_events = []
        
        # Generate scenario events (10% of total)
        if scenarios:
            scenario_event_count = int(total_events * 0.1)
            for scenario in scenarios:
                events_for_scenario = scenario_event_count // len(scenarios)
                scenario_events.extend(
                    self.generate_scenario_events(scenario, start_time, end_time, events_for_scenario)
                )
        
        # Generate normal events
        normal_event_count = total_events - len(scenario_events)
        
        for i in range(normal_event_count):
            timestamp = self.generate_timestamp(start_time, end_time)
            event = self.generate_event(timestamp, threat_probability=0.02)  # 2% baseline threat rate
            events.append(event)
        
        # Combine and sort by timestamp
        all_events = events + scenario_events
        all_events.sort(key=lambda x: x['event_time'])
        
        return all_events 