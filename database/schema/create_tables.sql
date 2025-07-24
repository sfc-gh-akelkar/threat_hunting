-- =====================================================
-- CyberCommand Database Schema
-- Snowflake Cybersecurity & SIEM Demo Application
-- =====================================================

-- Create database and schema
CREATE OR REPLACE DATABASE cyber_command;
USE DATABASE cyber_command;
CREATE OR REPLACE SCHEMA security_logs;
USE SCHEMA security_logs;

-- =====================================================
-- 1. NETWORK TRAFFIC LOGS
-- =====================================================
CREATE OR REPLACE TABLE network_logs (
    log_id STRING NOT NULL,
    event_time TIMESTAMP_LTZ NOT NULL,
    source_ip STRING NOT NULL,
    destination_ip STRING NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol STRING,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    bytes_transferred BIGINT GENERATED ALWAYS AS (bytes_sent + bytes_received),
    duration_ms INTEGER,
    connection_state STRING,
    user_id STRING,
    session_id STRING,
    source_hostname STRING,
    destination_hostname STRING,
    destination_domain STRING,
    application_protocol STRING,
    user_agent STRING,
    referrer STRING,
    response_code INTEGER,
    threat_score FLOAT DEFAULT 0.0,
    geolocation OBJECT,
    raw_log VARIANT,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- 2. AUTHENTICATION LOGS
-- =====================================================
CREATE OR REPLACE TABLE auth_logs (
    log_id STRING NOT NULL,
    event_time TIMESTAMP_LTZ NOT NULL,
    user_id STRING NOT NULL,
    username STRING,
    email STRING,
    auth_method STRING, -- password, mfa, sso, certificate
    auth_result STRING, -- success, failure, locked, expired
    source_ip STRING,
    source_hostname STRING,
    user_agent STRING,
    application STRING,
    service STRING,
    session_id STRING,
    failure_reason STRING,
    account_status STRING,
    role STRING,
    department STRING,
    geolocation OBJECT,
    risk_score FLOAT DEFAULT 0.0,
    mfa_method STRING,
    device_id STRING,
    device_trust_level STRING,
    raw_log VARIANT,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- 3. ENDPOINT SECURITY LOGS
-- =====================================================
CREATE OR REPLACE TABLE endpoint_logs (
    log_id STRING NOT NULL,
    event_time TIMESTAMP_LTZ NOT NULL,
    hostname STRING NOT NULL,
    user_id STRING,
    process_name STRING,
    process_id INTEGER,
    parent_process_id INTEGER,
    command_line STRING,
    file_path STRING,
    file_hash STRING,
    file_size BIGINT,
    event_type STRING, -- process_creation, file_access, network_connection, registry_modification
    event_action STRING, -- created, modified, deleted, executed, accessed
    source_ip STRING,
    destination_ip STRING,
    destination_port INTEGER,
    registry_key STRING,
    registry_value STRING,
    operating_system STRING,
    os_version STRING,
    agent_version STRING,
    severity STRING, -- low, medium, high, critical
    threat_detected BOOLEAN DEFAULT FALSE,
    threat_name STRING,
    threat_category STRING,
    mitigation_action STRING,
    raw_log VARIANT,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- 4. CLOUD SECURITY LOGS (AWS/Azure/GCP)
-- =====================================================
CREATE OR REPLACE TABLE cloud_logs (
    log_id STRING NOT NULL,
    event_time TIMESTAMP_LTZ NOT NULL,
    cloud_provider STRING, -- aws, azure, gcp
    account_id STRING,
    region STRING,
    service_name STRING,
    event_name STRING,
    event_source STRING,
    user_identity OBJECT,
    source_ip STRING,
    user_agent STRING,
    request_id STRING,
    api_version STRING,
    resources ARRAY,
    request_parameters OBJECT,
    response_elements OBJECT,
    error_code STRING,
    error_message STRING,
    event_category STRING, -- management, data, insight
    read_only BOOLEAN,
    resource_type STRING,
    resource_name STRING,
    aws_region STRING,
    vpc_id STRING,
    subnet_id STRING,
    security_group_ids ARRAY,
    raw_log VARIANT,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- 5. WEB APPLICATION LOGS
-- =====================================================
CREATE OR REPLACE TABLE web_logs (
    log_id STRING NOT NULL,
    event_time TIMESTAMP_LTZ NOT NULL,
    source_ip STRING NOT NULL,
    user_id STRING,
    session_id STRING,
    request_method STRING,
    request_url STRING,
    request_path STRING,
    query_parameters OBJECT,
    request_headers OBJECT,
    request_body STRING,
    response_status INTEGER,
    response_size BIGINT,
    response_time_ms INTEGER,
    user_agent STRING,
    referrer STRING,
    application STRING,
    server_name STRING,
    server_ip STRING,
    load_balancer STRING,
    ssl_protocol STRING,
    ssl_cipher STRING,
    threat_indicators ARRAY,
    attack_type STRING, -- sqli, xss, csrf, directory_traversal, brute_force
    blocked BOOLEAN DEFAULT FALSE,
    waf_rule_id STRING,
    geolocation OBJECT,
    raw_log VARIANT,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- 6. EMAIL SECURITY LOGS
-- =====================================================
CREATE OR REPLACE TABLE email_logs (
    log_id STRING NOT NULL,
    event_time TIMESTAMP_LTZ NOT NULL,
    message_id STRING NOT NULL,
    sender_email STRING,
    sender_domain STRING,
    sender_ip STRING,
    recipient_email STRING,
    recipient_domain STRING,
    subject STRING,
    message_size BIGINT,
    attachments ARRAY,
    attachment_hashes ARRAY,
    spam_score FLOAT,
    malware_detected BOOLEAN DEFAULT FALSE,
    malware_name STRING,
    phishing_detected BOOLEAN DEFAULT FALSE,
    action_taken STRING, -- delivered, quarantined, blocked, marked_spam
    email_gateway STRING,
    encryption_status STRING,
    authentication_results OBJECT, -- SPF, DKIM, DMARC
    threat_categories ARRAY,
    urls_extracted ARRAY,
    raw_log VARIANT,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- 7. THREAT INTELLIGENCE FEEDS
-- =====================================================
CREATE OR REPLACE TABLE threat_intel (
    indicator_id STRING NOT NULL,
    indicator STRING NOT NULL,
    indicator_type STRING NOT NULL, -- ip, domain, url, hash, email
    threat_type STRING, -- malware, c2, phishing, scanning, botnet
    threat_family STRING,
    confidence_score FLOAT, -- 0.0 to 1.0
    severity STRING, -- low, medium, high, critical
    source STRING, -- virustotal, alienvault, crowdstrike, etc.
    first_seen TIMESTAMP_LTZ,
    last_seen TIMESTAMP_LTZ,
    tags ARRAY,
    description STRING,
    references ARRAY,
    geolocation OBJECT,
    asn INTEGER,
    organization STRING,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- 8. SECURITY INCIDENTS
-- =====================================================
CREATE OR REPLACE TABLE security_incidents (
    incident_id STRING NOT NULL,
    title STRING NOT NULL,
    description STRING,
    severity STRING, -- low, medium, high, critical
    status STRING, -- new, assigned, investigating, resolved, closed
    category STRING, -- malware, data_breach, insider_threat, phishing, etc.
    assigned_to STRING,
    reporter STRING,
    affected_systems ARRAY,
    affected_users ARRAY,
    impact_assessment STRING,
    remediation_steps ARRAY,
    evidence_artifacts ARRAY,
    timeline ARRAY,
    tags ARRAY,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    resolved_at TIMESTAMP_LTZ,
    closed_at TIMESTAMP_LTZ
);

-- =====================================================
-- 9. USER ENTITIES AND CONTEXT
-- =====================================================
CREATE OR REPLACE TABLE users (
    user_id STRING NOT NULL,
    username STRING,
    email STRING,
    first_name STRING,
    last_name STRING,
    department STRING,
    title STRING,
    manager_id STRING,
    employee_id STRING,
    employee_type STRING, -- full_time, contractor, temp
    security_clearance STRING,
    account_status STRING, -- active, disabled, suspended
    last_login TIMESTAMP_LTZ,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    privileged_user BOOLEAN DEFAULT FALSE,
    risk_score FLOAT DEFAULT 0.0
);

-- =====================================================
-- 10. ASSETS AND DEVICES
-- =====================================================
CREATE OR REPLACE TABLE assets (
    asset_id STRING NOT NULL,
    hostname STRING,
    ip_address STRING,
    mac_address STRING,
    asset_type STRING, -- server, workstation, mobile, iot
    operating_system STRING,
    os_version STRING,
    owner STRING,
    department STRING,
    location STRING,
    criticality STRING, -- low, medium, high, critical
    security_zone STRING, -- dmz, internal, restricted
    last_seen TIMESTAMP_LTZ,
    vulnerability_score FLOAT DEFAULT 0.0,
    patch_level STRING,
    antivirus_status STRING,
    encryption_status STRING,
    created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- =====================================================
-- INDEXES AND CLUSTERING
-- =====================================================

-- Cluster network logs by time for better query performance
ALTER TABLE network_logs CLUSTER BY (event_time);

-- Cluster auth logs by user and time
ALTER TABLE auth_logs CLUSTER BY (user_id, event_time);

-- Cluster endpoint logs by hostname and time
ALTER TABLE endpoint_logs CLUSTER BY (hostname, event_time);

-- Cluster threat intel by indicator type
ALTER TABLE threat_intel CLUSTER BY (indicator_type);

-- =====================================================
-- VIEWS FOR COMMON QUERIES
-- =====================================================

-- High-risk network connections
CREATE OR REPLACE VIEW high_risk_connections AS
SELECT 
    nl.*,
    ti.threat_type,
    ti.confidence_score,
    ti.source as intel_source
FROM network_logs nl
LEFT JOIN threat_intel ti ON nl.destination_ip = ti.indicator
WHERE ti.confidence_score > 0.7 OR nl.threat_score > 0.5;

-- Failed authentication attempts
CREATE OR REPLACE VIEW failed_auth_attempts AS
SELECT 
    user_id,
    username,
    source_ip,
    COUNT(*) as failure_count,
    MIN(event_time) as first_failure,
    MAX(event_time) as last_failure,
    ARRAY_AGG(DISTINCT failure_reason) as failure_reasons
FROM auth_logs
WHERE auth_result = 'failure'
    AND event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP())
GROUP BY user_id, username, source_ip
HAVING COUNT(*) > 5;

-- Suspicious file activity
CREATE OR REPLACE VIEW suspicious_file_activity AS
SELECT 
    hostname,
    user_id,
    file_path,
    file_hash,
    COUNT(*) as access_count,
    ARRAY_AGG(DISTINCT event_action) as actions,
    MIN(event_time) as first_access,
    MAX(event_time) as last_access
FROM endpoint_logs
WHERE event_type = 'file_access'
    AND (file_path LIKE '%.exe' OR file_path LIKE '%.dll' OR file_path LIKE '%.bat')
    AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
GROUP BY hostname, user_id, file_path, file_hash
HAVING COUNT(*) > 10;

-- =====================================================
-- STORED PROCEDURES FOR THREAT HUNTING
-- =====================================================

-- Procedure to find data exfiltration patterns
CREATE OR REPLACE PROCEDURE find_data_exfiltration(days_back INTEGER)
RETURNS TABLE (user_id STRING, total_bytes BIGINT, connection_count INTEGER, unique_destinations INTEGER)
LANGUAGE SQL
AS
$$
    SELECT 
        user_id,
        SUM(bytes_transferred) as total_bytes,
        COUNT(*) as connection_count,
        COUNT(DISTINCT destination_ip) as unique_destinations
    FROM network_logs
    WHERE event_time >= DATEADD(day, -days_back, CURRENT_TIMESTAMP())
        AND bytes_transferred > 1000000  -- >1MB transfers
    GROUP BY user_id
    HAVING SUM(bytes_transferred) > 100000000  -- >100MB total
        OR COUNT(DISTINCT destination_ip) > 50
    ORDER BY total_bytes DESC;
$$;

-- Procedure to detect impossible travel
CREATE OR REPLACE PROCEDURE detect_impossible_travel(hours_threshold INTEGER)
RETURNS TABLE (user_id STRING, login1_time TIMESTAMP_LTZ, login1_location STRING, login2_time TIMESTAMP_LTZ, login2_location STRING, time_diff_hours FLOAT)
LANGUAGE SQL
AS
$$
    WITH user_logins AS (
        SELECT 
            user_id,
            event_time,
            source_ip,
            geolocation:country::STRING as country,
            geolocation:city::STRING as city,
            LAG(event_time) OVER (PARTITION BY user_id ORDER BY event_time) as prev_time,
            LAG(geolocation:country::STRING) OVER (PARTITION BY user_id ORDER BY event_time) as prev_country,
            LAG(geolocation:city::STRING) OVER (PARTITION BY user_id ORDER BY event_time) as prev_city
        FROM auth_logs
        WHERE auth_result = 'success'
            AND geolocation IS NOT NULL
            AND event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP())
    )
    SELECT 
        user_id,
        prev_time as login1_time,
        CONCAT(prev_city, ', ', prev_country) as login1_location,
        event_time as login2_time,
        CONCAT(city, ', ', country) as login2_location,
        DATEDIFF(hour, prev_time, event_time) as time_diff_hours
    FROM user_logins
    WHERE prev_country != country
        AND DATEDIFF(hour, prev_time, event_time) < hours_threshold
        AND DATEDIFF(hour, prev_time, event_time) > 0
    ORDER BY time_diff_hours ASC;
$$; 