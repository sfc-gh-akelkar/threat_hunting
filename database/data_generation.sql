-- =====================================================
-- CyberCommand Data Generation - Snowflake SQL Procedures
-- Generate realistic cybersecurity data directly in Snowflake
-- =====================================================

-- Use the correct database and schema
USE DATABASE cyber_command;
USE SCHEMA security_logs;

-- =====================================================
-- 1. HELPER FUNCTIONS FOR DATA GENERATION
-- =====================================================

-- Create sequences for unique IDs
CREATE OR REPLACE SEQUENCE log_id_seq START = 1 INCREMENT = 1;
CREATE OR REPLACE SEQUENCE user_seq START = 1 INCREMENT = 1;

-- =====================================================
-- 2. GENERATE USERS AND ASSETS
-- =====================================================

CREATE OR REPLACE PROCEDURE generate_users_and_assets()
RETURNS STRING
LANGUAGE SQL
AS
$$
BEGIN
    -- Generate users
    INSERT INTO users (
        user_id, username, email, first_name, last_name, 
        department, title, employee_type, security_clearance, 
        account_status, privileged_user, risk_score, created_at
    )
    SELECT 
        'user_' || seq4() as user_id,
        first_name || last_name as username,
        LOWER(first_name || '.' || last_name || '@company.com') as email,
        first_name,
        last_name,
        department,
        title,
        employee_type,
        security_clearance,
        'active' as account_status,
        CASE WHEN title LIKE '%Manager%' OR title LIKE '%Admin%' OR title LIKE '%CISO%' THEN TRUE ELSE FALSE END as privileged_user,
        UNIFORM(0.0, 0.3, RANDOM()) as risk_score,
        CURRENT_TIMESTAMP() as created_at
    FROM (
        SELECT 
            names.first_name,
            names.last_name,
            depts.department,
            depts.title,
            employee_types.employee_type,
            clearances.security_clearance
        FROM (
            SELECT column1 as first_name FROM VALUES 
                ('John'), ('Jane'), ('Michael'), ('Sarah'), ('David'), ('Emily'), 
                ('James'), ('Lisa'), ('Robert'), ('Maria'), ('William'), ('Jennifer'),
                ('Richard'), ('Patricia'), ('Thomas'), ('Linda'), ('Charles'), ('Barbara'),
                ('Christopher'), ('Elizabeth'), ('Daniel'), ('Jessica'), ('Matthew'), ('Susan'),
                ('Anthony'), ('Karen'), ('Mark'), ('Nancy'), ('Donald'), ('Betty')
        ) names
        CROSS JOIN (
            SELECT column1 as department, column2 as title FROM VALUES 
                ('Engineering', 'Software Engineer'), ('Engineering', 'Senior Engineer'), ('Engineering', 'Tech Lead'),
                ('Finance', 'Financial Analyst'), ('Finance', 'Accountant'), ('Finance', 'Finance Manager'),
                ('Sales', 'Sales Rep'), ('Sales', 'Account Manager'), ('Sales', 'Sales Manager'),
                ('Marketing', 'Marketing Specialist'), ('Marketing', 'Content Creator'), ('Marketing', 'Marketing Manager'),
                ('Security', 'Security Analyst'), ('Security', 'Security Engineer'), ('Security', 'CISO'),
                ('IT', 'IT Support'), ('IT', 'System Administrator'), ('IT', 'IT Manager'),
                ('HR', 'HR Coordinator'), ('HR', 'Recruiter'), ('HR', 'HR Manager'),
                ('Legal', 'Legal Counsel'), ('Operations', 'Operations Analyst'), ('Executive', 'VP')
        ) depts
        CROSS JOIN (
            SELECT column1 as employee_type FROM VALUES ('full_time'), ('contractor'), ('temp')
        ) employee_types
        CROSS JOIN (
            SELECT column1 as security_clearance FROM VALUES ('none'), ('confidential'), ('secret'), ('top_secret')
        ) clearances
        ORDER BY RANDOM()
        LIMIT 150
    );

    -- Generate assets
    INSERT INTO assets (
        asset_id, hostname, ip_address, mac_address, asset_type,
        operating_system, os_version, owner, department, location,
        criticality, security_zone, vulnerability_score, patch_level,
        antivirus_status, encryption_status, created_at
    )
    SELECT 
        'asset_' || seq4() as asset_id,
        asset_type || '-' || locations.location_code || '-' || LPAD(ROW_NUMBER() OVER (ORDER BY RANDOM()), 4, '0') as hostname,
        CASE locations.location_code
            WHEN 'SF' THEN '10.1.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            WHEN 'NY' THEN '10.2.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            WHEN 'LON' THEN '10.3.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            ELSE '10.4.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
        END as ip_address,
        CONCAT(
            LPAD(TO_HEX(FLOOR(UNIFORM(0, 256, RANDOM()))), 2, '0'), ':',
            LPAD(TO_HEX(FLOOR(UNIFORM(0, 256, RANDOM()))), 2, '0'), ':',
            LPAD(TO_HEX(FLOOR(UNIFORM(0, 256, RANDOM()))), 2, '0'), ':',
            LPAD(TO_HEX(FLOOR(UNIFORM(0, 256, RANDOM()))), 2, '0'), ':',
            LPAD(TO_HEX(FLOOR(UNIFORM(0, 256, RANDOM()))), 2, '0'), ':',
            LPAD(TO_HEX(FLOOR(UNIFORM(0, 256, RANDOM()))), 2, '0')
        ) as mac_address,
        asset_type,
        operating_system,
        os_version,
        'admin' as owner,
        'IT' as department,
        locations.location,
        criticalities.criticality,
        zones.security_zone,
        UNIFORM(0.0, 1.0, RANDOM()) as vulnerability_score,
        'current' as patch_level,
        'active' as antivirus_status,
        'enabled' as encryption_status,
        CURRENT_TIMESTAMP() as created_at
    FROM (
        SELECT column1 as asset_type, column2 as operating_system, column3 as os_version FROM VALUES 
            ('workstation', 'Windows 11', '22H2'),
            ('workstation', 'Windows 10', '21H2'),
            ('workstation', 'macOS Ventura', '13.0'),
            ('workstation', 'Ubuntu', '22.04'),
            ('server', 'Windows Server 2022', 'Standard'),
            ('server', 'Ubuntu Server', '20.04'),
            ('server', 'CentOS', '8'),
            ('mobile', 'iOS', '16.0'),
            ('mobile', 'Android', '13')
    ) asset_types
    CROSS JOIN (
        SELECT column1 as location, column2 as location_code FROM VALUES 
            ('San Francisco', 'SF'), ('New York', 'NY'), ('London', 'LON'), ('Singapore', 'SG')
    ) locations
    CROSS JOIN (
        SELECT column1 as criticality FROM VALUES ('low'), ('medium'), ('high'), ('critical')
    ) criticalities
    CROSS JOIN (
        SELECT column1 as security_zone FROM VALUES ('internal'), ('dmz'), ('restricted')
    ) zones
    ORDER BY RANDOM()
    LIMIT 500;

    RETURN 'Users and assets generated successfully!';
END;
$$;

-- =====================================================
-- 3. GENERATE THREAT INTELLIGENCE DATA
-- =====================================================

CREATE OR REPLACE PROCEDURE generate_threat_intelligence()
RETURNS STRING
LANGUAGE SQL
AS
$$
BEGIN
    -- Generate threat intelligence indicators
    INSERT INTO threat_intel (
        indicator_id, indicator, indicator_type, threat_type, threat_family,
        confidence_score, severity, source, first_seen, last_seen,
        tags, description, is_active, created_at
    )
    SELECT 
        'ti_' || seq4() as indicator_id,
        indicator,
        indicator_type,
        threat_type,
        threat_family,
        confidence_score,
        CASE 
            WHEN confidence_score > 0.8 THEN 'critical'
            WHEN confidence_score > 0.6 THEN 'high'
            WHEN confidence_score > 0.4 THEN 'medium'
            ELSE 'low'
        END as severity,
        source,
        DATEADD(day, -UNIFORM(1, 365, RANDOM()), CURRENT_TIMESTAMP()) as first_seen,
        DATEADD(day, -UNIFORM(0, 30, RANDOM()), CURRENT_TIMESTAMP()) as last_seen,
        ARRAY_CONSTRUCT(threat_type, 'automated') as tags,
        threat_type || ' indicator from ' || source as description,
        TRUE as is_active,
        CURRENT_TIMESTAMP() as created_at
    FROM (
        -- Malicious IPs
        SELECT 
            column1 as indicator,
            'ip' as indicator_type,
            column2 as threat_type,
            column3 as threat_family,
            UNIFORM(0.7, 0.95, RANDOM()) as confidence_score,
            column4 as source
        FROM VALUES 
            ('45.133.203.192', 'malware', 'APT1', 'VirusTotal'),
            ('185.220.101.32', 'c2', 'Lazarus', 'CrowdStrike'),
            ('198.98.51.189', 'scanning', 'Unknown', 'AlienVault'),
            ('103.253.27.108', 'botnet', 'Emotet', 'FireEye'),
            ('94.102.61.38', 'phishing', 'FIN7', 'Recorded Future'),
            ('178.128.83.165', 'ransomware', 'Conti', 'Mandiant')
        
        UNION ALL
        
        -- Malicious domains
        SELECT 
            column1 as indicator,
            'domain' as indicator_type,
            column2 as threat_type,
            column3 as threat_family,
            UNIFORM(0.8, 0.98, RANDOM()) as confidence_score,
            column4 as source
        FROM VALUES 
            ('evil-cdn.net', 'phishing', 'Generic', 'VirusTotal'),
            ('malware-host.com', 'malware', 'TrickBot', 'CrowdStrike'),
            ('c2-server.info', 'c2', 'Cobalt Strike', 'FireEye'),
            ('phishing-site.org', 'phishing', 'Generic', 'AlienVault'),
            ('bad-actor.biz', 'scanning', 'Unknown', 'SANS ISC'),
            ('threat-domain.xyz', 'data_theft', 'APT29', 'Mandiant')
        
        UNION ALL
        
        -- Malicious file hashes
        SELECT 
            SHA2(CONCAT('malware_', seq4()), 256) as indicator,
            'hash' as indicator_type,
            threat_types.threat_type,
            families.threat_family,
            UNIFORM(0.85, 0.99, RANDOM()) as confidence_score,
            sources.source
        FROM (
            SELECT column1 as threat_type FROM VALUES ('malware'), ('ransomware'), ('trojan'), ('backdoor'), ('rootkit')
        ) threat_types
        CROSS JOIN (
            SELECT column1 as threat_family FROM VALUES ('APT1'), ('Lazarus'), ('FIN7'), ('Carbanak'), ('Ryuk')
        ) families
        CROSS JOIN (
            SELECT column1 as source FROM VALUES ('VirusTotal'), ('CrowdStrike'), ('FireEye'), ('Kaspersky'), ('Symantec')
        ) sources
        LIMIT 50
    );

    RETURN 'Threat intelligence generated successfully!';
END;
$$;

-- =====================================================
-- 4. GENERATE NETWORK LOGS WITH THREAT SCENARIOS
-- =====================================================

CREATE OR REPLACE PROCEDURE generate_network_logs(days_back INTEGER DEFAULT 30, events_per_day INTEGER DEFAULT 10000)
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    start_date TIMESTAMP_LTZ := DATEADD(day, -days_back, CURRENT_TIMESTAMP());
    end_date TIMESTAMP_LTZ := CURRENT_TIMESTAMP();
    total_events INTEGER := days_back * events_per_day;
BEGIN
    -- Generate normal network traffic
    INSERT INTO network_logs (
        log_id, event_time, source_ip, destination_ip, source_port, destination_port,
        protocol, bytes_sent, bytes_received, duration_ms, connection_state,
        user_id, session_id, source_hostname, destination_hostname, destination_domain,
        application_protocol, user_agent, response_code, threat_score, geolocation
    )
    SELECT 
        'nl_' || log_id_seq.NEXTVAL as log_id,
        DATEADD(second, UNIFORM(0, days_back * 86400, RANDOM()), start_date) as event_time,
        
        -- Source IP (internal)
        CASE FLOOR(UNIFORM(1, 5, RANDOM()))
            WHEN 1 THEN '10.1.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            WHEN 2 THEN '10.2.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            WHEN 3 THEN '10.3.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            ELSE '10.4.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
        END as source_ip,
        
        -- Destination IP (mix of internal and external)
        CASE 
            WHEN UNIFORM(0, 1, RANDOM()) < 0.3 THEN 
                '10.' || FLOOR(UNIFORM(1, 5, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            ELSE 
                FLOOR(UNIFORM(1, 223, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
        END as destination_ip,
        
        FLOOR(UNIFORM(1024, 65535, RANDOM())) as source_port,
        ports.port as destination_port,
        protocols.protocol,
        FLOOR(UNIFORM(100, 50000, RANDOM())) as bytes_sent,
        FLOOR(UNIFORM(100, 500000, RANDOM())) as bytes_received,
        FLOOR(UNIFORM(100, 30000, RANDOM())) as duration_ms,
        conn_states.state as connection_state,
        
        -- User assignment
        users.user_id,
        'sess_' || FLOOR(UNIFORM(100000, 999999, RANDOM())) as session_id,
        users.user_id || '-laptop' as source_hostname,
        
        -- Destination hostname and domain
        CASE 
            WHEN UNIFORM(0, 1, RANDOM()) < 0.3 THEN 'server-' || FLOOR(UNIFORM(1, 100, RANDOM()))
            ELSE domains.domain
        END as destination_hostname,
        domains.domain as destination_domain,
        
        protocols.app_protocol as application_protocol,
        user_agents.agent as user_agent,
        CASE WHEN ports.port IN (80, 443) THEN response_codes.code ELSE NULL END as response_code,
        
        -- Threat score (mostly low for normal traffic)
        UNIFORM(0.0, 0.3, RANDOM()) as threat_score,
        
        -- Geolocation
        OBJECT_CONSTRUCT(
            'country', locations.country,
            'city', locations.city,
            'latitude', UNIFORM(-90, 90, RANDOM()),
            'longitude', UNIFORM(-180, 180, RANDOM())
        ) as geolocation
        
    FROM (
        SELECT ROW_NUMBER() OVER (ORDER BY RANDOM()) as rn
        FROM TABLE(GENERATOR(ROWCOUNT => total_events * 0.9)) -- 90% normal traffic
    ) gen
    CROSS JOIN (
        SELECT user_id FROM users ORDER BY RANDOM() LIMIT 1
    ) users
    CROSS JOIN (
        SELECT column1 as port, column2 as protocol, column3 as app_protocol FROM VALUES 
            (80, 'TCP', 'HTTP'), (443, 'TCP', 'HTTPS'), (22, 'TCP', 'SSH'),
            (25, 'TCP', 'SMTP'), (53, 'UDP', 'DNS'), (3389, 'TCP', 'RDP'),
            (5432, 'TCP', 'PostgreSQL'), (3306, 'TCP', 'MySQL')
        ORDER BY RANDOM() LIMIT 1
    ) ports
    CROSS JOIN (
        SELECT protocol FROM VALUES ('TCP'), ('UDP'), ('ICMP') ORDER BY RANDOM() LIMIT 1
    ) protocols
    CROSS JOIN (
        SELECT column1 as state FROM VALUES 
            ('ESTABLISHED'), ('SYN_SENT'), ('CLOSE_WAIT'), ('TIME_WAIT')
        ORDER BY RANDOM() LIMIT 1
    ) conn_states
    CROSS JOIN (
        SELECT column1 as domain FROM VALUES 
            ('github.com'), ('stackoverflow.com'), ('google.com'), ('microsoft.com'),
            ('aws.amazon.com'), ('slack.com'), ('zoom.us'), ('office365.com')
        ORDER BY RANDOM() LIMIT 1
    ) domains
    CROSS JOIN (
        SELECT column1 as agent FROM VALUES 
            ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'),
            ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'),
            ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
        ORDER BY RANDOM() LIMIT 1
    ) user_agents
    CROSS JOIN (
        SELECT column1 as code FROM VALUES (200), (301), (302), (404), (403), (500)
        ORDER BY RANDOM() LIMIT 1
    ) response_codes
    CROSS JOIN (
        SELECT column1 as country, column2 as city FROM VALUES 
            ('United States', 'San Francisco'), ('United States', 'New York'),
            ('United Kingdom', 'London'), ('Singapore', 'Singapore')
        ORDER BY RANDOM() LIMIT 1
    ) locations;

    -- Generate threat scenario data (10% of traffic)
    CALL generate_phantom_exfiltrator_scenario(days_back, FLOOR(total_events * 0.1));

    RETURN 'Network logs generated successfully! Events: ' || total_events;
END;
$$;

-- =====================================================
-- 5. GENERATE "PHANTOM EXFILTRATOR" THREAT SCENARIO
-- =====================================================

CREATE OR REPLACE PROCEDURE generate_phantom_exfiltrator_scenario(days_back INTEGER, event_count INTEGER)
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    start_date TIMESTAMP_LTZ := DATEADD(day, -days_back, CURRENT_TIMESTAMP());
BEGIN
    -- Generate suspicious data exfiltration events
    INSERT INTO network_logs (
        log_id, event_time, source_ip, destination_ip, source_port, destination_port,
        protocol, bytes_sent, bytes_received, duration_ms, connection_state,
        user_id, session_id, source_hostname, destination_hostname, destination_domain,
        application_protocol, threat_score, geolocation
    )
    SELECT 
        'nl_threat_' || log_id_seq.NEXTVAL as log_id,
        
        -- Time bias towards after hours (evenings/weekends)
        CASE 
            WHEN UNIFORM(0, 1, RANDOM()) < 0.6 THEN
                DATEADD(hour, UNIFORM(18, 23, RANDOM()), DATE_TRUNC('day', DATEADD(day, -UNIFORM(0, days_back, RANDOM()), CURRENT_TIMESTAMP())))
            ELSE
                DATEADD(second, UNIFORM(0, days_back * 86400, RANDOM()), start_date)
        END as event_time,
        
        '10.1.' || FLOOR(UNIFORM(100, 200, RANDOM())) || '.' || FLOOR(UNIFORM(1, 50, RANDOM())) as source_ip,
        
        -- Use threat intelligence IPs
        threat_ips.indicator as destination_ip,
        FLOOR(UNIFORM(1024, 65535, RANDOM())) as source_port,
        443 as destination_port,
        'TCP' as protocol,
        
        -- Large data transfers (10MB - 500MB)
        FLOOR(UNIFORM(10000000, 500000000, RANDOM())) as bytes_sent,
        FLOOR(UNIFORM(1000, 10000, RANDOM())) as bytes_received,
        FLOOR(UNIFORM(30000, 300000, RANDOM())) as duration_ms,
        'ESTABLISHED' as connection_state,
        
        -- Target specific users
        target_users.user_id,
        'sess_threat_' || FLOOR(UNIFORM(100000, 999999, RANDOM())) as session_id,
        target_users.user_id || '-laptop' as source_hostname,
        threat_domains.indicator as destination_hostname,
        threat_domains.indicator as destination_domain,
        'HTTPS' as application_protocol,
        
        -- High threat score
        UNIFORM(0.7, 0.9, RANDOM()) as threat_score,
        
        -- Suspicious geolocation
        OBJECT_CONSTRUCT(
            'country', threat_locations.country,
            'city', 'Unknown',
            'latitude', UNIFORM(-90, 90, RANDOM()),
            'longitude', UNIFORM(-180, 180, RANDOM()),
            'threat_level', 'high'
        ) as geolocation
        
    FROM (
        SELECT ROW_NUMBER() OVER (ORDER BY RANDOM()) as rn
        FROM TABLE(GENERATOR(ROWCOUNT => event_count))
    ) gen
    CROSS JOIN (
        -- Target users for the scenario
        SELECT user_id FROM users WHERE user_id IN (
            SELECT user_id FROM users WHERE department IN ('Engineering', 'Finance') ORDER BY RANDOM() LIMIT 3
        ) ORDER BY RANDOM() LIMIT 1
    ) target_users
    CROSS JOIN (
        SELECT indicator FROM threat_intel WHERE indicator_type = 'ip' ORDER BY RANDOM() LIMIT 1
    ) threat_ips
    CROSS JOIN (
        SELECT indicator FROM threat_intel WHERE indicator_type = 'domain' ORDER BY RANDOM() LIMIT 1
    ) threat_domains
    CROSS JOIN (
        SELECT column1 as country FROM VALUES ('Russia'), ('China'), ('North Korea'), ('Iran')
        ORDER BY RANDOM() LIMIT 1
    ) threat_locations;

    RETURN 'Phantom Exfiltrator scenario generated successfully!';
END;
$$;

-- =====================================================
-- 6. GENERATE AUTHENTICATION LOGS
-- =====================================================

CREATE OR REPLACE PROCEDURE generate_auth_logs(days_back INTEGER DEFAULT 30, events_per_day INTEGER DEFAULT 5000)
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    total_events INTEGER := days_back * events_per_day;
    start_date TIMESTAMP_LTZ := DATEADD(day, -days_back, CURRENT_TIMESTAMP());
BEGIN
    INSERT INTO auth_logs (
        log_id, event_time, user_id, username, email, auth_method, auth_result,
        source_ip, source_hostname, user_agent, application, service, session_id,
        failure_reason, account_status, role, department, geolocation, risk_score,
        mfa_method, device_id, device_trust_level
    )
    SELECT 
        'al_' || log_id_seq.NEXTVAL as log_id,
        DATEADD(second, UNIFORM(0, days_back * 86400, RANDOM()), start_date) as event_time,
        users.user_id,
        users.username,
        users.email,
        auth_methods.method as auth_method,
        
        -- Auth result (90% success, 10% failure)
        CASE WHEN UNIFORM(0, 1, RANDOM()) < 0.9 THEN 'success' ELSE 'failure' END as auth_result,
        
        CASE 
            WHEN UNIFORM(0, 1, RANDOM()) < 0.8 THEN 
                '10.' || FLOOR(UNIFORM(1, 5, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
            ELSE 
                FLOOR(UNIFORM(1, 223, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM())) || '.' || FLOOR(UNIFORM(1, 255, RANDOM()))
        END as source_ip,
        
        users.user_id || '-device' as source_hostname,
        user_agents.agent as user_agent,
        applications.app as application,
        'authentication' as service,
        'sess_' || FLOOR(UNIFORM(100000, 999999, RANDOM())) as session_id,
        
        CASE WHEN UNIFORM(0, 1, RANDOM()) < 0.9 THEN NULL ELSE failure_reasons.reason END as failure_reason,
        users.account_status,
        users.title as role,
        users.department,
        
        OBJECT_CONSTRUCT(
            'country', locations.country,
            'city', locations.city,
            'latitude', UNIFORM(-90, 90, RANDOM()),
            'longitude', UNIFORM(-180, 180, RANDOM())
        ) as geolocation,
        
        UNIFORM(0.0, 0.4, RANDOM()) as risk_score,
        mfa_methods.method as mfa_method,
        'device_' || FLOOR(UNIFORM(1000, 9999, RANDOM())) as device_id,
        trust_levels.level as device_trust_level
        
    FROM (
        SELECT ROW_NUMBER() OVER (ORDER BY RANDOM()) as rn
        FROM TABLE(GENERATOR(ROWCOUNT => total_events))
    ) gen
    CROSS JOIN (
        SELECT * FROM users ORDER BY RANDOM() LIMIT 1
    ) users
    CROSS JOIN (
        SELECT column1 as method FROM VALUES ('password'), ('mfa'), ('sso'), ('certificate')
        ORDER BY RANDOM() LIMIT 1
    ) auth_methods
    CROSS JOIN (
        SELECT column1 as agent FROM VALUES 
            ('Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
            ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'),
            ('Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)')
        ORDER BY RANDOM() LIMIT 1
    ) user_agents
    CROSS JOIN (
        SELECT column1 as app FROM VALUES ('Snowflake'), ('Slack'), ('Office365'), ('GitHub'), ('AWS Console')
        ORDER BY RANDOM() LIMIT 1
    ) applications
    CROSS JOIN (
        SELECT column1 as reason FROM VALUES 
            ('invalid_password'), ('account_locked'), ('expired_password'), ('invalid_mfa')
        ORDER BY RANDOM() LIMIT 1
    ) failure_reasons
    CROSS JOIN (
        SELECT column1 as country, column2 as city FROM VALUES 
            ('United States', 'San Francisco'), ('United States', 'New York'),
            ('United Kingdom', 'London'), ('Singapore', 'Singapore'),
            ('Canada', 'Toronto'), ('Germany', 'Berlin')
        ORDER BY RANDOM() LIMIT 1
    ) locations
    CROSS JOIN (
        SELECT column1 as method FROM VALUES ('app'), ('sms'), ('hardware_token'), ('biometric')
        ORDER BY RANDOM() LIMIT 1
    ) mfa_methods
    CROSS JOIN (
        SELECT column1 as level FROM VALUES ('trusted'), ('known'), ('unknown'), ('suspicious')
        ORDER BY RANDOM() LIMIT 1
    ) trust_levels;

    RETURN 'Authentication logs generated successfully! Events: ' || total_events;
END;
$$;

-- =====================================================
-- 7. MASTER DATA GENERATION PROCEDURE
-- =====================================================

CREATE OR REPLACE PROCEDURE generate_all_demo_data(
    days_back INTEGER DEFAULT 30,
    network_events_per_day INTEGER DEFAULT 10000,
    auth_events_per_day INTEGER DEFAULT 5000
)
RETURNS STRING
LANGUAGE SQL
AS
$$
DECLARE
    result STRING := '';
BEGIN
    -- Clear existing data
    DELETE FROM network_logs;
    DELETE FROM auth_logs;
    DELETE FROM threat_intel;
    DELETE FROM users;
    DELETE FROM assets;
    
    -- Generate reference data
    CALL generate_users_and_assets();
    result := result || 'Users and assets generated. ';
    
    CALL generate_threat_intelligence();
    result := result || 'Threat intelligence generated. ';
    
    -- Generate log data
    CALL generate_network_logs(days_back, network_events_per_day);
    result := result || 'Network logs generated. ';
    
    CALL generate_auth_logs(days_back, auth_events_per_day);
    result := result || 'Authentication logs generated. ';
    
    -- Update statistics
    result := result || 'Data generation complete! ';
    result := result || 'Total network events: ' || (SELECT COUNT(*) FROM network_logs) || '. ';
    result := result || 'Total auth events: ' || (SELECT COUNT(*) FROM auth_logs) || '. ';
    result := result || 'Total users: ' || (SELECT COUNT(*) FROM users) || '. ';
    
    RETURN result;
END;
$$; 