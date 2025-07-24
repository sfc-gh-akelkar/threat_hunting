#!/usr/bin/env python3
"""
Main script for generating cybersecurity demo data
"""
import os
import sys
import json
import csv
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd

# Add the generators directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'generators'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'config'))

from generators.network_generator import NetworkLogGenerator
from config.generation_config import *

def setup_output_directory(output_dir: str) -> Path:
    """Create output directory structure"""
    base_path = Path(output_dir)
    
    # Create subdirectories for each log type
    subdirs = ['network_logs', 'auth_logs', 'endpoint_logs', 'web_logs', 
               'email_logs', 'cloud_logs', 'threat_intel', 'users', 'assets']
    
    for subdir in subdirs:
        (base_path / subdir).mkdir(parents=True, exist_ok=True)
    
    return base_path

def save_events(events: list, 
                output_path: Path, 
                filename: str, 
                format: str = 'json'):
    """Save events to file in specified format"""
    
    filepath = output_path / f"{filename}.{format}"
    
    if format == 'json':
        with open(filepath, 'w') as f:
            # Convert datetime objects to strings for JSON serialization
            json_events = []
            for event in events:
                json_event = {}
                for key, value in event.items():
                    if isinstance(value, datetime):
                        json_event[key] = value.isoformat()
                    else:
                        json_event[key] = value
                json_events.append(json_event)
            
            json.dump(json_events, f, indent=2, default=str)
    
    elif format == 'csv':
        if events:
            # Flatten nested objects for CSV
            flattened_events = []
            for event in events:
                flat_event = {}
                for key, value in event.items():
                    if isinstance(value, dict):
                        # Flatten nested objects
                        for nested_key, nested_value in value.items():
                            flat_event[f"{key}_{nested_key}"] = nested_value
                    elif isinstance(value, list):
                        # Convert lists to comma-separated strings
                        flat_event[key] = ','.join(str(item) for item in value)
                    else:
                        flat_event[key] = value
                flattened_events.append(flat_event)
            
            df = pd.DataFrame(flattened_events)
            df.to_csv(filepath, index=False)
    
    elif format == 'parquet':
        df = pd.DataFrame(events)
        df.to_parquet(filepath, index=False)
    
    print(f"✅ Saved {len(events)} events to {filepath}")

def generate_reference_data(config: dict, output_path: Path):
    """Generate reference data (users, assets, threat intel)"""
    
    print("🔧 Generating reference data...")
    
    # Generate users
    from generators.base_generator import BaseSecurityGenerator
    base_gen = BaseSecurityGenerator(config)
    
    all_users = []
    for dept in config.get('DEPARTMENTS', []):
        users = base_gen._user_cache.get(dept, [])
        if not users:
            # Force generation of users for this department
            base_gen.generate_user_id(dept)
            users = base_gen._user_cache.get(dept, [])
        all_users.extend(users)
    
    save_events(all_users, output_path / 'users', 'users', 'json')
    save_events(all_users, output_path / 'users', 'users', 'csv')
    
    # Generate assets
    all_assets = []
    for asset_type in ['workstation', 'server', 'mobile']:
        assets = base_gen._asset_cache.get(asset_type, [])
        if not assets:
            base_gen.generate_hostname(asset_type)
            assets = base_gen._asset_cache.get(asset_type, [])
        all_assets.extend(assets)
    
    save_events(all_assets, output_path / 'assets', 'assets', 'json')
    save_events(all_assets, output_path / 'assets', 'assets', 'csv')
    
    # Generate threat intelligence
    threat_intel = base_gen._threat_indicators
    threat_intel_formatted = []
    
    for indicator in threat_intel:
        intel_record = {
            'indicator_id': base_gen.generate_log_id(),
            'indicator': indicator['indicator'],
            'indicator_type': indicator['type'],
            'threat_type': indicator['threat_type'],
            'confidence_score': indicator['confidence'],
            'severity': 'high' if indicator['confidence'] > 0.8 else 'medium',
            'source': indicator['source'],
            'first_seen': datetime.now() - timedelta(days=random.randint(1, 365)),
            'last_seen': datetime.now() - timedelta(days=random.randint(0, 30)),
            'tags': [indicator['threat_type'], 'automated'],
            'description': f"{indicator['threat_type'].title()} indicator from {indicator['source']}",
            'is_active': True
        }
        threat_intel_formatted.append(intel_record)
    
    save_events(threat_intel_formatted, output_path / 'threat_intel', 'threat_intel', 'json')
    save_events(threat_intel_formatted, output_path / 'threat_intel', 'threat_intel', 'csv')

def generate_network_logs(config: dict, output_path: Path, args):
    """Generate network traffic logs"""
    
    print("🌐 Generating network logs...")
    
    generator = NetworkLogGenerator(config)
    
    # Calculate event counts
    daily_events = config.get('DAILY_EVENT_COUNTS', {}).get('network_logs', 50000)
    if args.sample:
        daily_events = min(daily_events, 1000)  # Limit for sample data
    
    # Generate events with scenarios
    scenarios = ['phantom_exfiltrator', 'insider_threat'] if args.scenarios else None
    
    events = generator.generate_bulk_events(
        start_time=config.get('START_DATE', datetime.now() - timedelta(days=30)),
        end_time=config.get('END_DATE', datetime.now()),
        events_per_day=daily_events,
        scenarios=scenarios
    )
    
    # Save in requested formats
    for fmt in args.formats:
        save_events(events, output_path / 'network_logs', 'network_logs', fmt)
    
    return len(events)

def main():
    parser = argparse.ArgumentParser(description='Generate cybersecurity demo data')
    parser.add_argument('--output', '-o', default='./output', 
                      help='Output directory (default: ./output)')
    parser.add_argument('--formats', nargs='+', choices=['json', 'csv', 'parquet'],
                      default=['json'], help='Output formats (default: json)')
    parser.add_argument('--scenarios', action='store_true',
                      help='Include threat scenarios in generated data')
    parser.add_argument('--sample', action='store_true',
                      help='Generate smaller sample dataset for testing')
    parser.add_argument('--days', type=int, default=30,
                      help='Number of days of data to generate (default: 30)')
    parser.add_argument('--log-types', nargs='+', 
                      choices=['network', 'auth', 'endpoint', 'web', 'email', 'cloud', 'all'],
                      default=['all'], help='Types of logs to generate (default: all)')
    
    args = parser.parse_args()
    
    # Update configuration based on arguments
    config = {
        'START_DATE': datetime.now() - timedelta(days=args.days),
        'END_DATE': datetime.now(),
        'DAILY_EVENT_COUNTS': DAILY_EVENT_COUNTS,
        'DEPARTMENTS': DEPARTMENTS,
        'USER_ROLES': USER_ROLES,
        'SECURITY_CLEARANCES': SECURITY_CLEARANCES,
        'OFFICE_LOCATIONS': OFFICE_LOCATIONS,
        'THREAT_LOCATIONS': THREAT_LOCATIONS,
        'THREAT_SCENARIOS': THREAT_SCENARIOS,
        'THREAT_INTEL_SOURCES': THREAT_INTEL_SOURCES,
        'APPLICATIONS': APPLICATIONS,
        'OPERATING_SYSTEMS': OPERATING_SYSTEMS
    }
    
    print("🚀 CyberCommand Data Generator")
    print(f"📊 Generating {args.days} days of data")
    print(f"💾 Output directory: {args.output}")
    print(f"📄 Output formats: {', '.join(args.formats)}")
    print(f"🎭 Include scenarios: {args.scenarios}")
    print(f"🔬 Sample mode: {args.sample}")
    print()
    
    # Setup output directory
    output_path = setup_output_directory(args.output)
    
    # Generate reference data first
    generate_reference_data(config, output_path)
    
    # Generate log types
    total_events = 0
    
    if 'network' in args.log_types or 'all' in args.log_types:
        total_events += generate_network_logs(config, output_path, args)
    
    # TODO: Add other log type generators
    # if 'auth' in args.log_types or 'all' in args.log_types:
    #     total_events += generate_auth_logs(config, output_path, args)
    
    print()
    print("✨ Generation complete!")
    print(f"📈 Total events generated: {total_events:,}")
    print(f"📁 Output directory: {output_path.absolute()}")
    
    # Generate summary report
    summary = {
        'generation_time': datetime.now().isoformat(),
        'parameters': {
            'days': args.days,
            'scenarios_included': args.scenarios,
            'sample_mode': args.sample,
            'log_types': args.log_types
        },
        'output': {
            'directory': str(output_path.absolute()),
            'formats': args.formats,
            'total_events': total_events
        },
        'scenarios': {
            'phantom_exfiltrator': {
                'description': 'APT actor using living-off-the-land techniques for data theft',
                'target_users': ['jsmith', 'alee', 'mchen'],
                'indicators': 'Large file transfers, off-hours access, unusual destinations'
            },
            'insider_threat': {
                'description': 'Employee planning to steal data before leaving company',
                'target_users': ['bwilson'],
                'indicators': 'After-hours access, bulk downloads, unusual file access'
            }
        } if args.scenarios else {}
    }
    
    with open(output_path / 'generation_summary.json', 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"📋 Summary saved to: {output_path / 'generation_summary.json'}")

if __name__ == '__main__':
    main() 