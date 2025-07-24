# CyberCommand Dashboard
## Snowflake Cybersecurity & SIEM Demo Application

A comprehensive threat hunting and security analytics platform demonstrating Snowflake's capabilities for cybersecurity data analysis.

## Features

### 🔍 Threat Hunting
- Interactive SQL query builder for security investigations
- Real-time anomaly detection and behavioral analytics
- Historical analysis with Snowflake's Time Travel feature
- Collaborative investigation workflows

### 📊 Security Analytics
- Multi-source log aggregation and correlation
- Threat intelligence enrichment
- Compliance reporting and metrics
- Advanced visualizations for security data

### 🛡️ Data Sources
- Network traffic logs
- Authentication and access logs
- Endpoint security events
- Threat intelligence feeds
- Cloud security logs (AWS, Azure, GCP)

## Project Structure

```
cyber_app/
├── database/
│   ├── schema/          # Snowflake table definitions
│   ├── seeds/           # Initial data and lookups
│   └── migrations/      # Schema evolution scripts
├── data-generation/
│   ├── generators/      # Data generation scripts
│   ├── scenarios/       # Threat scenario templates
│   └── config/          # Generation parameters
├── backend/
│   ├── api/            # REST API endpoints
│   ├── connectors/     # Snowflake and external integrations
│   └── ml/             # ML models for anomaly detection
├── frontend/
│   ├── components/     # React components
│   ├── dashboards/     # Security dashboards
│   └── utils/          # Helper functions
└── docs/               # Documentation and demo scripts
```

## Quick Start

1. **Setup Database Schema**
   ```bash
   # Run schema creation scripts
   snowsql -f database/schema/create_tables.sql
   ```

2. **Generate Sample Data**
   ```bash
   python data-generation/generate_security_data.py
   ```

3. **Start the Application**
   ```bash
   # Backend
   cd backend && npm start
   
   # Frontend
   cd frontend && npm start
   ```

## Demo Scenarios

### "The Phantom Exfiltrator"
Sophisticated APT actor using living-off-the-land techniques for data theft.

### "Insider Threat Detection"
Behavioral analysis to identify suspicious employee activities.

### "Supply Chain Compromise"
Tracking malicious code through software dependencies.

## Snowflake Capabilities Demonstrated

- **Massive Scale Analytics**: Query billions of security events in seconds
- **Time Travel**: Historical investigation and forensic analysis
- **Data Sharing**: Secure threat intelligence collaboration
- **Semi-structured Data**: JSON log parsing and analysis
- **Elastic Scaling**: Handle variable analytical workloads
- **Security & Governance**: Fine-grained access controls 
