# 🚀 CyberCommand Data Generation in Snowflake Worksheets

This guide shows you how to generate realistic cybersecurity data directly in Snowflake worksheets, keeping everything within the Snowflake ecosystem.

## 📋 Prerequisites

1. **Snowflake Account** with appropriate permissions
2. **Database and Schema** created (run `snowflake_setup.sql` first)
3. **Tables created** (run `database/schema/create_tables.sql`)
4. **Access to Snowflake Worksheets** in Snowsight

---

## 🎯 Step-by-Step Data Generation

### **Step 1: Set Context**
```sql
-- Set the correct database and schema
USE DATABASE cyber_command;
USE SCHEMA security_logs;
USE WAREHOUSE cybercommand_wh;
```

### **Step 2: Create Data Generation Procedures**
Copy and paste the entire content of `database/data_generation.sql` into a Snowflake worksheet and execute it. This will create all the necessary stored procedures.

### **Step 3: Generate Sample Data**
Run this single command to generate a complete dataset:

```sql
-- Generate 30 days of data with realistic volumes
CALL generate_all_demo_data(
    30,     -- days_back: 30 days of historical data
    10000,  -- network_events_per_day: 10K network events per day
    5000    -- auth_events_per_day: 5K authentication events per day
);
```

**Expected Output:**
```
Users and assets generated. Threat intelligence generated. Network logs generated. Authentication logs generated. Data generation complete! Total network events: 300000. Total auth events: 150000. Total users: 150.
```

---

## 🔧 Customization Options

### **Adjust Data Volume**
```sql
-- For a smaller demo (good for testing)
CALL generate_all_demo_data(7, 1000, 500);

-- For a larger demo (more realistic volumes)
CALL generate_all_demo_data(90, 50000, 25000);
```

### **Generate Specific Data Types**
```sql
-- Generate only network logs
CALL generate_network_logs(30, 10000);

-- Generate only authentication logs  
CALL generate_auth_logs(30, 5000);

-- Generate only threat intelligence
CALL generate_threat_intelligence();

-- Generate only users and assets
CALL generate_users_and_assets();
```

### **Add More Threat Scenarios**
```sql
-- Generate additional "Phantom Exfiltrator" events
CALL generate_phantom_exfiltrator_scenario(30, 1000);
```

---

## 📊 Verify Data Generation

### **Check Data Volumes**
```sql
-- Verify data was generated successfully
SELECT 'network_logs' as table_name, COUNT(*) as record_count FROM network_logs
UNION ALL
SELECT 'auth_logs' as table_name, COUNT(*) as record_count FROM auth_logs  
UNION ALL
SELECT 'threat_intel' as table_name, COUNT(*) as record_count FROM threat_intel
UNION ALL
SELECT 'users' as table_name, COUNT(*) as record_count FROM users
UNION ALL
SELECT 'assets' as table_name, COUNT(*) as record_count FROM assets;
```

### **Check Data Quality**
```sql
-- Verify data spans the expected time range
SELECT 
    MIN(event_time) as earliest_event,
    MAX(event_time) as latest_event,
    DATEDIFF(day, MIN(event_time), MAX(event_time)) as days_span
FROM network_logs;
```

### **Preview Threat Scenarios**
```sql
-- Check for high-threat events (Phantom Exfiltrator scenario)
SELECT 
    user_id,
    destination_ip,
    destination_domain,
    bytes_transferred,
    threat_score,
    event_time
FROM network_logs 
WHERE threat_score > 0.7
ORDER BY threat_score DESC, bytes_transferred DESC
LIMIT 10;
```

---

## 🎭 Built-in Threat Scenarios

### **1. The Phantom Exfiltrator**
This scenario generates:
- **Large data transfers** (10MB - 500MB per event)
- **After-hours activity** (evenings and weekends)
- **Suspicious destinations** (using threat intelligence IPs/domains)
- **Target users** from Engineering and Finance departments
- **High threat scores** (0.7 - 0.9)

### **2. Behavioral Anomalies** 
The data includes:
- **Impossible travel patterns** (rapid geographic changes)
- **Unusual authentication patterns** (multiple failed logins)
- **Off-hours access** (outside business hours)
- **Suspicious locations** (threat actor countries)

---

## 🔍 Data Exploration Queries

### **Find Data Exfiltration Patterns**
```sql
SELECT 
    user_id,
    COUNT(*) as large_transfers,
    SUM(bytes_transferred) as total_bytes,
    COUNT(DISTINCT destination_ip) as unique_destinations
FROM network_logs 
WHERE bytes_transferred > 50000000  -- >50MB
    AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
GROUP BY user_id
HAVING COUNT(*) > 5
ORDER BY total_bytes DESC;
```

### **Detect Impossible Travel**
```sql
WITH user_locations AS (
    SELECT 
        user_id,
        event_time,
        geolocation:country::STRING as country,
        LAG(event_time) OVER (PARTITION BY user_id ORDER BY event_time) as prev_time,
        LAG(geolocation:country::STRING) OVER (PARTITION BY user_id ORDER BY event_time) as prev_country
    FROM auth_logs
    WHERE geolocation IS NOT NULL
)
SELECT 
    user_id,
    prev_country || ' → ' || country as travel_path,
    DATEDIFF(hour, prev_time, event_time) as hours_between_logins
FROM user_locations
WHERE prev_country != country
    AND DATEDIFF(hour, prev_time, event_time) < 8
ORDER BY hours_between_logins;
```

### **Threat Intelligence Matches**
```sql
SELECT 
    nl.user_id,
    nl.destination_ip,
    nl.bytes_transferred,
    ti.threat_type,
    ti.confidence_score,
    nl.event_time
FROM network_logs nl
JOIN threat_intel ti ON nl.destination_ip = ti.indicator
WHERE ti.is_active = TRUE
ORDER BY ti.confidence_score DESC, nl.bytes_transferred DESC
LIMIT 20;
```

---

## ⚡ Performance Tips

### **Use Appropriate Warehouse Size**
```sql
-- For data generation (one-time activity)
ALTER WAREHOUSE cybercommand_wh SET WAREHOUSE_SIZE = 'LARGE';

-- After generation, scale down for queries
ALTER WAREHOUSE cybercommand_wh SET WAREHOUSE_SIZE = 'MEDIUM';
```

### **Monitor Generation Progress**
```sql
-- Check progress during generation
SELECT COUNT(*) as records_so_far FROM network_logs;
```

### **Optimize for Demo Performance**
```sql
-- Create clustering keys for better query performance
ALTER TABLE network_logs CLUSTER BY (event_time);
ALTER TABLE auth_logs CLUSTER BY (user_id, event_time);
```

---

## 🎯 Demo-Ready Scenarios

After data generation, your CyberCommand application will have:

✅ **150 realistic users** across different departments and roles  
✅ **500 assets** including workstations, servers, and mobile devices  
✅ **Comprehensive threat intelligence** with IPs, domains, and file hashes  
✅ **300,000+ network events** with embedded threat scenarios  
✅ **150,000+ authentication events** with behavioral anomalies  
✅ **Pre-built hunting scenarios** ready for demonstration  

---

## 🆘 Troubleshooting

### **If Generation Fails:**
1. **Check permissions**: Ensure you have `CREATE PROCEDURE` privileges
2. **Verify warehouse**: Make sure the warehouse is running and sized appropriately
3. **Check resources**: Large data generation may require bigger warehouses

### **If Data Looks Unrealistic:**
1. **Adjust parameters**: Modify event counts and time ranges
2. **Re-run specific scenarios**: Use individual procedures to fine-tune data
3. **Check threat scenarios**: Verify threat events have high scores and realistic patterns

### **Performance Issues:**
1. **Scale up warehouse**: Use LARGE or X-LARGE for initial generation
2. **Run in batches**: Generate smaller date ranges sequentially
3. **Monitor credits**: Watch Snowflake credit consumption during generation

---

## 🎬 Ready for Demo!

Once data generation is complete, your Streamlit in Snowflake application will have realistic, threat-rich data perfect for demonstrating:

- 🔍 **Interactive threat hunting** with real attack patterns
- 📊 **Advanced security analytics** across multiple data sources  
- 🎯 **Threat intelligence correlation** with live IOCs
- ⏰ **Time Travel investigations** using historical data
- 🤝 **Collaborative workflows** for security teams

**Next Step:** Launch your CyberCommand Streamlit app and start hunting! 🚀 