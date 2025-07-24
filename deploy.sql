-- =====================================================
-- CyberCommand Streamlit in Snowflake Deployment Script
-- =====================================================

-- Use the appropriate role and context
USE ROLE cybercommand_admin;
USE WAREHOUSE cybercommand_wh;
USE DATABASE cyber_command;
USE SCHEMA security_logs;

-- Upload Streamlit application files to stage
-- Note: These PUT commands should be run from SnowSQL with access to local files

-- Main application file
PUT file://streamlit_app.py @streamlit_stage AUTO_COMPRESS=FALSE OVERWRITE=TRUE;

-- Page files
PUT file://pages/1_🔍_Threat_Hunting.py @streamlit_stage/pages/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
PUT file://pages/2_📊_Analytics.py @streamlit_stage/pages/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE;

-- Environment configuration
PUT file://environment.yml @streamlit_stage AUTO_COMPRESS=FALSE OVERWRITE=TRUE;

-- Verify files are uploaded
LIST @streamlit_stage;

-- Update Streamlit application to point to the new files
ALTER STREAMLIT cybercommand_app SET 
    ROOT_LOCATION = '@cyber_command.security_logs.streamlit_stage'
    MAIN_FILE = '/streamlit_app.py'
    QUERY_WAREHOUSE = 'cybercommand_wh';

-- Show Streamlit applications
SHOW STREAMLITS;

-- Get the application URL
SELECT 
    system$get_streamlit_url('cybercommand_app') as app_url,
    'Application deployed successfully!' as status,
    'Click the URL above to access CyberCommand' as instructions; 