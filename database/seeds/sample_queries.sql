-- =====================================================
-- Sample Threat Hunting Queries for CyberCommand Demo
-- Showcasing Snowflake's Analytical Capabilities
-- =====================================================

-- Use the cybersecurity database
USE DATABASE cyber_command;
USE SCHEMA security_logs;

-- =====================================================
-- 1. DATA EXFILTRATION HUNTING
-- =====================================================

-- Find users with unusual large data transfers
SELECT 
    user_id,
    COUNT(*) as transfer_count,
    SUM(bytes_transferred) as total_bytes,
    AVG(bytes_transferred) as avg_bytes,
    COUNT(DISTINCT destination_ip) as unique_destinations,
    ARRAY_AGG(DISTINCT destination_domain) as domains_contacted
FROM network_logs 
WHERE event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP())
    AND bytes_transferred > 10000000  -- >10MB transfers
GROUP BY user_id
HAVING SUM(bytes_transferred) > 500000000  -- >500MB total
    OR COUNT(DISTINCT destination_ip) > 20
ORDER BY total_bytes DESC;

-- Correlate large transfers with authentication patterns
WITH suspicious_transfers AS (
    SELECT user_id, event_time, destination_ip, bytes_transferred
    FROM network_logs 
    WHERE bytes_transferred > 50000000  -- >50MB
        AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
),
auth_context AS (
    SELECT user_id, event_time as login_time, source_ip, geolocation
    FROM auth_logs 
    WHERE auth_result = 'success'
        AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
)
SELECT 
    st.user_id,
    st.event_time as transfer_time,
    st.destination_ip,
    st.bytes_transferred,
    ac.login_time,
    ac.source_ip as login_ip,
    ac.geolocation:country::STRING as login_country,
    DATEDIFF(minute, ac.login_time, st.event_time) as minutes_after_login
FROM suspicious_transfers st
LEFT JOIN auth_context ac ON st.user_id = ac.user_id
    AND ac.login_time <= st.event_time
    AND ac.login_time >= DATEADD(hour, -2, st.event_time)
ORDER BY st.bytes_transferred DESC;

-- =====================================================
-- 2. IMPOSSIBLE TRAVEL DETECTION
-- =====================================================

-- Detect impossible travel patterns using Time Travel for historical context
WITH user_locations AS (
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
    prev_time as first_login,
    CONCAT(prev_city, ', ', prev_country) as first_location,
    event_time as second_login,
    CONCAT(city, ', ', country) as second_location,
    DATEDIFF(hour, prev_time, event_time) as time_diff_hours,
    -- Calculate theoretical minimum travel time (assuming 500mph commercial flight)
    CASE 
        WHEN prev_country != country THEN 8  -- International travel minimum
        WHEN prev_city != city THEN 2        -- Domestic travel minimum
        ELSE 0
    END as min_travel_hours
FROM user_locations
WHERE prev_country IS NOT NULL
    AND prev_country != country
    AND DATEDIFF(hour, prev_time, event_time) < 8  -- Less than 8 hours for international travel
ORDER BY time_diff_hours ASC;

-- =====================================================
-- 3. BEHAVIORAL ANOMALY DETECTION
-- =====================================================

-- Find users accessing systems outside normal hours
WITH normal_hours AS (
    SELECT 
        user_id,
        EXTRACT(hour FROM event_time) as hour_of_day,
        COUNT(*) as access_count
    FROM auth_logs
    WHERE auth_result = 'success'
        AND event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP())
        AND EXTRACT(hour FROM event_time) BETWEEN 9 AND 17  -- Normal business hours
    GROUP BY user_id, hour_of_day
),
after_hours AS (
    SELECT 
        user_id,
        COUNT(*) as after_hours_count,
        ARRAY_AGG(DISTINCT EXTRACT(hour FROM event_time)) as after_hours_list
    FROM auth_logs
    WHERE auth_result = 'success'
        AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
        AND (EXTRACT(hour FROM event_time) < 9 OR EXTRACT(hour FROM event_time) > 17)
    GROUP BY user_id
)
SELECT 
    ah.user_id,
    ah.after_hours_count,
    ah.after_hours_list,
    AVG(nh.access_count) as avg_normal_hours_access,
    -- Calculate anomaly score
    ah.after_hours_count / NULLIF(AVG(nh.access_count), 0) as anomaly_ratio
FROM after_hours ah
LEFT JOIN normal_hours nh ON ah.user_id = nh.user_id
GROUP BY ah.user_id, ah.after_hours_count, ah.after_hours_list
HAVING ah.after_hours_count > 5  -- More than 5 after-hours accesses
ORDER BY anomaly_ratio DESC;

-- =====================================================
-- 4. THREAT INTELLIGENCE ENRICHMENT
-- =====================================================

-- Correlate network traffic with threat intelligence
SELECT 
    nl.event_time,
    nl.user_id,
    nl.source_ip,
    nl.destination_ip,
    nl.destination_domain,
    nl.bytes_transferred,
    ti.threat_type,
    ti.confidence_score,
    ti.source as intel_source,
    ti.description,
    -- Risk scoring based on multiple factors
    CASE 
        WHEN ti.confidence_score > 0.9 THEN 'CRITICAL'
        WHEN ti.confidence_score > 0.7 THEN 'HIGH'
        WHEN ti.confidence_score > 0.5 THEN 'MEDIUM'
        ELSE 'LOW'
    END as risk_level
FROM network_logs nl
INNER JOIN threat_intel ti ON nl.destination_ip = ti.indicator
WHERE nl.event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
    AND ti.is_active = TRUE
ORDER BY ti.confidence_score DESC, nl.bytes_transferred DESC;

-- =====================================================
-- 5. LATERAL MOVEMENT DETECTION
-- =====================================================

-- Detect potential lateral movement using network connections
WITH internal_connections AS (
    SELECT 
        user_id,
        source_ip,
        destination_ip,
        COUNT(*) as connection_count,
        COUNT(DISTINCT destination_ip) as unique_destinations,
        MAX(event_time) as last_connection
    FROM network_logs
    WHERE source_ip LIKE '10.%'  -- Internal source
        AND destination_ip LIKE '10.%'  -- Internal destination
        AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
    GROUP BY user_id, source_ip, destination_ip
),
user_baselines AS (
    SELECT 
        user_id,
        AVG(unique_destinations) as avg_destinations,
        STDDEV(unique_destinations) as stddev_destinations
    FROM (
        SELECT user_id, source_ip, COUNT(DISTINCT destination_ip) as unique_destinations
        FROM network_logs
        WHERE source_ip LIKE '10.%' AND destination_ip LIKE '10.%'
            AND event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP())
        GROUP BY user_id, source_ip, DATE(event_time)
    )
    GROUP BY user_id
)
SELECT 
    ic.user_id,
    ic.source_ip,
    ic.unique_destinations,
    ub.avg_destinations,
    -- Calculate z-score for anomaly detection
    (ic.unique_destinations - ub.avg_destinations) / NULLIF(ub.stddev_destinations, 0) as z_score,
    ic.last_connection
FROM internal_connections ic
INNER JOIN user_baselines ub ON ic.user_id = ub.user_id
WHERE (ic.unique_destinations - ub.avg_destinations) / NULLIF(ub.stddev_destinations, 0) > 2  -- 2 standard deviations
ORDER BY z_score DESC;

-- =====================================================
-- 6. TIME TRAVEL INVESTIGATION
-- =====================================================

-- Use Snowflake Time Travel to investigate what we might have missed
-- Example: Check if suspicious activity existed 30 days ago
SELECT 
    'CURRENT' as time_period,
    COUNT(*) as suspicious_events,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(bytes_transferred) as total_bytes
FROM network_logs
WHERE threat_score > 0.7
    AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())

UNION ALL

SELECT 
    '30_DAYS_AGO' as time_period,
    COUNT(*) as suspicious_events,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(bytes_transferred) as total_bytes
FROM network_logs AT(TIMESTAMP => DATEADD(day, -30, CURRENT_TIMESTAMP()))
WHERE threat_score > 0.7
    AND event_time >= DATEADD(day, -37, CURRENT_TIMESTAMP())
    AND event_time <= DATEADD(day, -30, CURRENT_TIMESTAMP());

-- =====================================================
-- 7. ADVANCED THREAT HUNTING WITH ML FUNCTIONS
-- =====================================================

-- Use Snowflake's built-in statistical functions for anomaly detection
WITH daily_user_activity AS (
    SELECT 
        user_id,
        DATE(event_time) as activity_date,
        COUNT(*) as daily_events,
        SUM(bytes_transferred) as daily_bytes,
        COUNT(DISTINCT destination_ip) as daily_destinations
    FROM network_logs
    WHERE event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP())
    GROUP BY user_id, DATE(event_time)
),
user_statistics AS (
    SELECT 
        user_id,
        AVG(daily_events) as avg_events,
        STDDEV(daily_events) as stddev_events,
        AVG(daily_bytes) as avg_bytes,
        STDDEV(daily_bytes) as stddev_bytes,
        AVG(daily_destinations) as avg_destinations,
        STDDEV(daily_destinations) as stddev_destinations
    FROM daily_user_activity
    GROUP BY user_id
),
current_activity AS (
    SELECT 
        user_id,
        COUNT(*) as current_events,
        SUM(bytes_transferred) as current_bytes,
        COUNT(DISTINCT destination_ip) as current_destinations
    FROM network_logs
    WHERE DATE(event_time) = CURRENT_DATE()
    GROUP BY user_id
)
SELECT 
    ca.user_id,
    ca.current_events,
    us.avg_events,
    -- Z-score for events
    (ca.current_events - us.avg_events) / NULLIF(us.stddev_events, 0) as events_z_score,
    ca.current_bytes,
    us.avg_bytes,
    -- Z-score for bytes
    (ca.current_bytes - us.avg_bytes) / NULLIF(us.stddev_bytes, 0) as bytes_z_score,
    ca.current_destinations,
    us.avg_destinations,
    -- Z-score for destinations
    (ca.current_destinations - us.avg_destinations) / NULLIF(us.stddev_destinations, 0) as destinations_z_score,
    -- Overall anomaly score (average of absolute z-scores)
    (ABS((ca.current_events - us.avg_events) / NULLIF(us.stddev_events, 0)) + 
     ABS((ca.current_bytes - us.avg_bytes) / NULLIF(us.stddev_bytes, 0)) + 
     ABS((ca.current_destinations - us.avg_destinations) / NULLIF(us.stddev_destinations, 0))) / 3 as overall_anomaly_score
FROM current_activity ca
INNER JOIN user_statistics us ON ca.user_id = us.user_id
WHERE (ABS((ca.current_events - us.avg_events) / NULLIF(us.stddev_events, 0)) > 2
    OR ABS((ca.current_bytes - us.avg_bytes) / NULLIF(us.stddev_bytes, 0)) > 2
    OR ABS((ca.current_destinations - us.avg_destinations) / NULLIF(us.stddev_destinations, 0)) > 2)
ORDER BY overall_anomaly_score DESC;

-- =====================================================
-- 8. COLLABORATIVE INVESTIGATION QUERIES
-- =====================================================

-- Create a shared view for ongoing investigation
CREATE OR REPLACE SECURE VIEW phantom_exfiltrator_investigation AS
SELECT 
    nl.event_time,
    nl.user_id,
    u.first_name || ' ' || u.last_name as full_name,
    u.department,
    nl.source_ip,
    nl.destination_ip,
    nl.destination_domain,
    nl.bytes_transferred,
    nl.threat_score,
    ti.threat_type,
    ti.confidence_score as intel_confidence,
    -- Investigation notes (would be updated by analysts)
    CASE 
        WHEN nl.user_id IN ('jsmith', 'alee', 'mchen') THEN 'TARGET USER - Monitor closely'
        WHEN nl.bytes_transferred > 100000000 THEN 'LARGE TRANSFER - Investigate'
        WHEN ti.confidence_score > 0.8 THEN 'HIGH CONFIDENCE THREAT - Priority'
        ELSE 'NORMAL ACTIVITY'
    END as investigation_status
FROM network_logs nl
LEFT JOIN users u ON nl.user_id = u.user_id
LEFT JOIN threat_intel ti ON nl.destination_ip = ti.indicator
WHERE nl.event_time >= DATEADD(day, -45, CURRENT_TIMESTAMP())  -- Phantom Exfiltrator timeline
    AND (nl.threat_score > 0.5 OR ti.confidence_score > 0.7)
ORDER BY nl.event_time DESC;

-- Query the investigation view
SELECT 
    investigation_status,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(bytes_transferred) as total_bytes_transferred
FROM phantom_exfiltrator_investigation
GROUP BY investigation_status
ORDER BY event_count DESC; 