"""
Configuration for cybersecurity data generation
"""
from datetime import datetime, timedelta
from typing import Dict, List, Any

# ============================================
# GENERATION PARAMETERS
# ============================================

# Time range for data generation
START_DATE = datetime.now() - timedelta(days=90)  # 90 days of data
END_DATE = datetime.now()

# Data volume settings
DAILY_EVENT_COUNTS = {
    'network_logs': 50000,      # 50K network events per day
    'auth_logs': 25000,         # 25K auth events per day
    'endpoint_logs': 30000,     # 30K endpoint events per day
    'web_logs': 40000,          # 40K web requests per day
    'email_logs': 5000,         # 5K email events per day
    'cloud_logs': 10000,        # 10K cloud events per day
}

# ============================================
# ORGANIZATIONAL STRUCTURE
# ============================================

DEPARTMENTS = [
    'Engineering', 'Sales', 'Marketing', 'Finance', 'HR', 'Legal', 
    'Operations', 'Security', 'IT', 'Executive', 'Support', 'Research'
]

USER_ROLES = {
    'Engineering': ['Software Engineer', 'Senior Engineer', 'Tech Lead', 'Engineering Manager', 'DevOps Engineer'],
    'Sales': ['Sales Rep', 'Account Manager', 'Sales Manager', 'VP Sales'],
    'Marketing': ['Marketing Specialist', 'Content Creator', 'Marketing Manager', 'VP Marketing'],
    'Finance': ['Accountant', 'Financial Analyst', 'Finance Manager', 'CFO'],
    'HR': ['HR Coordinator', 'Recruiter', 'HR Manager', 'VP HR'],
    'Legal': ['Legal Counsel', 'Paralegal', 'General Counsel'],
    'Operations': ['Operations Analyst', 'Operations Manager', 'VP Operations'],
    'Security': ['Security Analyst', 'Security Engineer', 'CISO'],
    'IT': ['IT Support', 'System Administrator', 'IT Manager', 'CTO'],
    'Executive': ['CEO', 'President', 'VP'],
    'Support': ['Support Rep', 'Senior Support', 'Support Manager'],
    'Research': ['Researcher', 'Data Scientist', 'Research Manager']
}

SECURITY_CLEARANCES = ['none', 'confidential', 'secret', 'top_secret']

# ============================================
# NETWORK AND INFRASTRUCTURE
# ============================================

# Internal IP ranges
INTERNAL_IP_RANGES = [
    '10.0.0.0/8',
    '192.168.0.0/16',
    '172.16.0.0/12'
]

# Common applications and services
APPLICATIONS = {
    'web': ['salesforce', 'slack', 'github', 'jira', 'confluence', 'office365'],
    'databases': ['postgresql', 'mysql', 'mongodb', 'snowflake', 'redshift'],
    'cloud': ['aws-s3', 'aws-ec2', 'azure-storage', 'gcp-compute'],
    'security': ['okta', 'duo', 'splunk', 'crowdstrike', 'palo-alto']
}

# Operating systems
OPERATING_SYSTEMS = [
    'Windows 10', 'Windows 11', 'macOS Monterey', 'macOS Ventura', 
    'Ubuntu 20.04', 'Ubuntu 22.04', 'CentOS 7', 'RHEL 8'
]

# ============================================
# THREAT SCENARIOS
# ============================================

THREAT_SCENARIOS = {
    'phantom_exfiltrator': {
        'name': 'The Phantom Exfiltrator',
        'description': 'APT actor using living-off-the-land techniques for data theft',
        'duration_days': 45,
        'target_users': ['jsmith', 'alee', 'mchen'],
        'target_departments': ['Engineering', 'Finance'],
        'indicators': {
            'large_file_transfers': True,
            'off_hours_access': True,
            'unusual_destinations': True,
            'privilege_escalation': True,
            'lateral_movement': True
        },
        'timeline': [
            {'day': 1, 'phase': 'reconnaissance', 'activities': ['port_scanning', 'dns_enumeration']},
            {'day': 7, 'phase': 'initial_access', 'activities': ['phishing_email', 'credential_theft']},
            {'day': 14, 'phase': 'persistence', 'activities': ['backdoor_installation', 'scheduled_tasks']},
            {'day': 21, 'phase': 'lateral_movement', 'activities': ['credential_dumping', 'remote_access']},
            {'day': 35, 'phase': 'data_discovery', 'activities': ['file_enumeration', 'database_queries']},
            {'day': 42, 'phase': 'exfiltration', 'activities': ['data_compression', 'encrypted_transfer']}
        ]
    },
    'insider_threat': {
        'name': 'Disgruntled Employee',
        'description': 'Employee planning to steal data before leaving company',
        'duration_days': 30,
        'target_users': ['bwilson'],
        'target_departments': ['Sales'],
        'indicators': {
            'after_hours_access': True,
            'bulk_downloads': True,
            'access_to_unusual_files': True,
            'external_storage_usage': True
        }
    },
    'supply_chain_attack': {
        'name': 'Compromised Software Update',
        'description': 'Malicious code injected through software supply chain',
        'duration_days': 60,
        'target_systems': ['build-server-01', 'repo-server-02'],
        'indicators': {
            'unsigned_binaries': True,
            'network_beaconing': True,
            'process_injection': True,
            'registry_modifications': True
        }
    }
}

# ============================================
# GEOGRAPHIC LOCATIONS
# ============================================

OFFICE_LOCATIONS = {
    'headquarters': {
        'city': 'San Francisco',
        'country': 'United States',
        'timezone': 'America/Los_Angeles',
        'ip_range': '10.1.0.0/16',
        'employees': 500
    },
    'east_coast': {
        'city': 'New York',
        'country': 'United States', 
        'timezone': 'America/New_York',
        'ip_range': '10.2.0.0/16',
        'employees': 300
    },
    'europe': {
        'city': 'London',
        'country': 'United Kingdom',
        'timezone': 'Europe/London',
        'ip_range': '10.3.0.0/16',
        'employees': 200
    },
    'apac': {
        'city': 'Singapore',
        'country': 'Singapore',
        'timezone': 'Asia/Singapore',
        'ip_range': '10.4.0.0/16',
        'employees': 150
    }
}

# Suspicious/malicious locations
THREAT_LOCATIONS = [
    {'city': 'Unknown', 'country': 'Russia', 'threat_level': 'high'},
    {'city': 'Unknown', 'country': 'China', 'threat_level': 'high'},
    {'city': 'Unknown', 'country': 'North Korea', 'threat_level': 'critical'},
    {'city': 'Tor Exit Node', 'country': 'Various', 'threat_level': 'medium'},
    {'city': 'Unknown', 'country': 'Iran', 'threat_level': 'high'},
]

# ============================================
# THREAT INTELLIGENCE DATA
# ============================================

THREAT_INTEL_SOURCES = [
    'VirusTotal', 'AlienVault OTX', 'ThreatCrowd', 'IBM X-Force', 
    'Recorded Future', 'CrowdStrike', 'FireEye', 'Mandiant',
    'Symantec', 'Kaspersky', 'SANS ISC', 'Abuse.ch'
]

MALWARE_FAMILIES = [
    'APT1', 'Lazarus', 'Carbanak', 'FIN7', 'Cobalt Strike', 'Emotet',
    'TrickBot', 'Ryuk', 'Maze', 'Sodinokibi', 'DarkSide', 'Conti'
]

ATTACK_TYPES = [
    'malware', 'phishing', 'c2', 'scanning', 'botnet', 'ransomware',
    'data_theft', 'credential_harvesting', 'ddos', 'cryptomining'
]

# ============================================
# NORMAL BEHAVIOR PATTERNS
# ============================================

WORK_HOURS = {
    'headquarters': (9, 18),    # 9 AM - 6 PM PST
    'east_coast': (9, 18),      # 9 AM - 6 PM EST
    'europe': (9, 17),          # 9 AM - 5 PM GMT
    'apac': (9, 18),            # 9 AM - 6 PM SGT
}

WEEKEND_ACTIVITY_RATE = 0.05   # 5% of normal activity on weekends
HOLIDAY_ACTIVITY_RATE = 0.02   # 2% of normal activity on holidays

# Common file extensions by department
DEPARTMENT_FILE_PATTERNS = {
    'Engineering': ['.py', '.js', '.java', '.cpp', '.h', '.sql', '.json', '.yaml'],
    'Finance': ['.xlsx', '.csv', '.pdf', '.docx', '.ppt'],
    'Legal': ['.docx', '.pdf', '.txt'],
    'Marketing': ['.pdf', '.ppt', '.jpg', '.png', '.mp4'],
    'Sales': ['.pdf', '.xlsx', '.ppt', '.docx'],
    'HR': ['.pdf', '.docx', '.xlsx']
}

# ============================================
# EXPORT CONFIGURATION
# ============================================

# Output settings
OUTPUT_FORMATS = ['json', 'csv', 'parquet']
BATCH_SIZE = 10000
COMPRESSION = 'gzip'

# Snowflake connection (if direct upload needed)
SNOWFLAKE_CONFIG = {
    'account': 'your_account',
    'warehouse': 'DEMO_WH',
    'database': 'CYBER_COMMAND',
    'schema': 'SECURITY_LOGS',
    'role': 'DEMO_ROLE'
} 