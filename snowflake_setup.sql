-- =====================================================
-- CyberCommand Streamlit in Snowflake Setup
-- =====================================================

-- 1. Create the application database and schema
CREATE OR REPLACE DATABASE cyber_command;
USE DATABASE cyber_command;
CREATE OR REPLACE SCHEMA security_logs;
USE SCHEMA security_logs;

-- 2. Create a dedicated warehouse for the SiS app
CREATE OR REPLACE WAREHOUSE cybercommand_wh
    WAREHOUSE_SIZE = 'MEDIUM'
    AUTO_SUSPEND = 300
    AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'Warehouse for CyberCommand Streamlit in Snowflake Application';

-- 3. Create roles for the application
CREATE OR REPLACE ROLE cybercommand_admin;
CREATE OR REPLACE ROLE cybercommand_analyst;
CREATE OR REPLACE ROLE cybercommand_viewer;

-- 4. Grant privileges to roles
-- Admin role (full access)
GRANT USAGE ON WAREHOUSE cybercommand_wh TO ROLE cybercommand_admin;
GRANT USAGE ON DATABASE cyber_command TO ROLE cybercommand_admin;
GRANT USAGE ON SCHEMA cyber_command.security_logs TO ROLE cybercommand_admin;
GRANT CREATE TABLE ON SCHEMA cyber_command.security_logs TO ROLE cybercommand_admin;
GRANT CREATE VIEW ON SCHEMA cyber_command.security_logs TO ROLE cybercommand_admin;
GRANT CREATE STREAMLIT ON SCHEMA cyber_command.security_logs TO ROLE cybercommand_admin;

-- Analyst role (read/write access to data)
GRANT USAGE ON WAREHOUSE cybercommand_wh TO ROLE cybercommand_analyst;
GRANT USAGE ON DATABASE cyber_command TO ROLE cybercommand_analyst;
GRANT USAGE ON SCHEMA cyber_command.security_logs TO ROLE cybercommand_analyst;

-- Viewer role (read-only access)
GRANT USAGE ON WAREHOUSE cybercommand_wh TO ROLE cybercommand_viewer;
GRANT USAGE ON DATABASE cyber_command TO ROLE cybercommand_viewer;
GRANT USAGE ON SCHEMA cyber_command.security_logs TO ROLE cybercommand_viewer;

-- 5. Create the Streamlit application
USE ROLE cybercommand_admin;
USE WAREHOUSE cybercommand_wh;
USE DATABASE cyber_command;
USE SCHEMA security_logs;

CREATE OR REPLACE STREAMLIT cybercommand_app
    ROOT_LOCATION = '@cyber_command.security_logs.streamlit_stage'
    MAIN_FILE = '/streamlit_app.py'
    QUERY_WAREHOUSE = 'cybercommand_wh'
    COMMENT = 'CyberCommand - Advanced Threat Hunting & Security Analytics Platform';

-- 6. Create internal stage for Streamlit files
CREATE OR REPLACE STAGE streamlit_stage
    DIRECTORY = (ENABLE = TRUE)
    COMMENT = 'Stage for CyberCommand Streamlit application files';

-- 7. Grant permissions on the Streamlit app
GRANT USAGE ON STREAMLIT cybercommand_app TO ROLE cybercommand_analyst;
GRANT USAGE ON STREAMLIT cybercommand_app TO ROLE cybercommand_viewer;

-- 8. Create sample data loading procedures
CREATE OR REPLACE PROCEDURE load_sample_data()
    RETURNS STRING
    LANGUAGE SQL
    EXECUTE AS CALLER
AS
$$
BEGIN
    -- This procedure would load sample data from the generated files
    -- In practice, this would use COPY INTO commands to load from stage
    
    LET result STRING := 'Sample data loading procedure created. Use data generation scripts to populate tables.';
    RETURN result;
END;
$$;

-- 9. Create data quality monitoring views
CREATE OR REPLACE VIEW data_quality_summary AS
SELECT 
    'network_logs' as table_name,
    COUNT(*) as record_count,
    MIN(event_time) as earliest_event,
    MAX(event_time) as latest_event,
    COUNT(DISTINCT user_id) as unique_users
FROM network_logs
UNION ALL
SELECT 
    'auth_logs' as table_name,
    COUNT(*) as record_count,
    MIN(event_time) as earliest_event,
    MAX(event_time) as latest_event,
    COUNT(DISTINCT user_id) as unique_users
FROM auth_logs
UNION ALL
SELECT 
    'endpoint_logs' as table_name,
    COUNT(*) as record_count,
    MIN(event_time) as earliest_event,
    MAX(event_time) as latest_event,
    COUNT(DISTINCT user_id) as unique_users
FROM endpoint_logs;

-- 10. Setup complete - display application URL
SELECT 'CyberCommand Streamlit in Snowflake application setup complete!' as status,
       'Use SHOW STREAMLITS to view application details' as next_step,
       'Access the app through Snowsight -> Streamlit' as access_instructions; 