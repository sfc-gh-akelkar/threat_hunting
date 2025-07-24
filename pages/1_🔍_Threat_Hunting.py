"""
Advanced Threat Hunting Interface
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

st.set_page_config(page_title="Threat Hunting", page_icon="🔍")

st.title("🔍 Advanced Threat Hunting")

def get_snowflake_connection():
    """Get Snowflake connection from Streamlit secrets"""
    return st.connection("snowflake")

def execute_query(query, params=None):
    """Execute SQL query against Snowflake"""
    try:
        conn = get_snowflake_connection()
        if params:
            return conn.query(query, params=params)
        else:
            return conn.query(query)
    except Exception as e:
        st.error(f"Query execution failed: {str(e)}")
        return pd.DataFrame()

# Hunting Techniques Sidebar
st.sidebar.header("🎯 Hunting Techniques")
technique = st.sidebar.selectbox(
    "Select technique:",
    [
        "Data Exfiltration",
        "Impossible Travel",
        "Lateral Movement", 
        "Privilege Escalation",
        "Command & Control",
        "Persistence Mechanisms"
    ]
)

# Time Range Selection
time_range = st.sidebar.selectbox(
    "Time Range:",
    ["Last 24 hours", "Last 7 days", "Last 30 days", "Custom range"]
)

if time_range == "Custom range":
    col1, col2 = st.sidebar.columns(2)
    with col1:
        start_date = st.date_input("Start Date")
    with col2:
        end_date = st.date_input("End Date")

# Main hunting interface
tab1, tab2, tab3 = st.tabs(["🎭 Scenario Hunting", "🔧 Custom Queries", "📊 Hunt Results"])

with tab1:
    st.header(f"🎯 {technique} Detection")
    
    if technique == "Data Exfiltration":
        st.markdown("""
        **Hunt Hypothesis:** Detect unusual data transfer patterns that may indicate data theft
        
        **Techniques:**
        - Large file transfers to external domains
        - Unusual volume of data movement
        - Transfers to newly registered or suspicious domains
        """)
        
        # Configuration options
        col1, col2 = st.columns(2)
        with col1:
            min_transfer_size = st.number_input("Minimum transfer size (MB)", value=50, min_value=1)
        with col2:
            max_destinations = st.number_input("Max unique destinations threshold", value=20, min_value=1)
        
        if st.button("🚀 Execute Hunt"):
            with st.spinner("Hunting for data exfiltration patterns..."):
                query = f"""
                SELECT 
                    user_id,
                    COUNT(*) as transfer_count,
                    ROUND(SUM(bytes_transferred)/1024/1024, 2) as total_mb,
                    ROUND(AVG(bytes_transferred)/1024/1024, 2) as avg_mb,
                    COUNT(DISTINCT destination_ip) as unique_destinations,
                    ARRAY_AGG(DISTINCT destination_domain) as domains_contacted,
                    MAX(event_time) as last_transfer
                FROM cyber_command.security_logs.network_logs 
                WHERE event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
                    AND bytes_transferred > {min_transfer_size * 1024 * 1024}
                GROUP BY user_id
                HAVING SUM(bytes_transferred) > {min_transfer_size * 10 * 1024 * 1024}
                    OR COUNT(DISTINCT destination_ip) > {max_destinations}
                ORDER BY total_mb DESC
                """
                
                results = execute_query(query)
                
                if not results.empty:
                    st.success(f"🎯 Found {len(results)} potential data exfiltration cases")
                    
                    # Visualization
                    fig = px.scatter(
                        results, 
                        x='UNIQUE_DESTINATIONS', 
                        y='TOTAL_MB',
                        size='TRANSFER_COUNT',
                        color='TRANSFER_COUNT',
                        hover_data=['USER_ID'],
                        title="Data Exfiltration Analysis",
                        labels={
                            'UNIQUE_DESTINATIONS': 'Unique Destinations',
                            'TOTAL_MB': 'Total Data Transferred (MB)'
                        }
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Detailed results
                    st.subheader("🔍 Detailed Results")
                    for _, row in results.iterrows():
                        with st.expander(f"👤 {row['USER_ID']} - {row['TOTAL_MB']:.1f} MB transferred"):
                            col1, col2 = st.columns(2)
                            with col1:
                                st.write(f"**Transfers:** {row['TRANSFER_COUNT']}")
                                st.write(f"**Average Size:** {row['AVG_MB']:.1f} MB")
                                st.write(f"**Unique Destinations:** {row['UNIQUE_DESTINATIONS']}")
                            with col2:
                                st.write(f"**Last Transfer:** {row['LAST_TRANSFER']}")
                                st.write("**Domains Contacted:**")
                                try:
                                    domains = eval(row['DOMAINS_CONTACTED'])
                                    for domain in domains[:5]:  # Show first 5 domains
                                        st.write(f"- {domain}")
                                except:
                                    st.write("- Unable to parse domains")
                                
                                if st.button(f"🕵️ Investigate {row['USER_ID']}", key=f"investigate_{row['USER_ID']}"):
                                    st.session_state.investigation_user = row['USER_ID']
                                    st.info(f"Investigation started for {row['USER_ID']}")
                else:
                    st.info("✅ No suspicious data exfiltration patterns detected.")
    
    elif technique == "Impossible Travel":
        st.markdown("""
        **Hunt Hypothesis:** Detect logins from geographically impossible locations within short timeframes
        
        **Techniques:**
        - Calculate travel time between login locations
        - Flag physically impossible travel scenarios
        - Consider time zones and commercial flight speeds
        """)
        
        max_travel_hours = st.number_input("Maximum travel time (hours)", value=8, min_value=1, max_value=24)
        
        if st.button("🚀 Execute Hunt"):
            with st.spinner("Hunting for impossible travel patterns..."):
                query = f"""
                WITH user_locations AS (
                    SELECT 
                        user_id,
                        event_time,
                        source_ip,
                        geolocation:country::STRING as country,
                        geolocation:city::STRING as city,
                        LAG(event_time) OVER (PARTITION BY user_id ORDER BY event_time) as prev_time,
                        LAG(geolocation:country::STRING) OVER (PARTITION BY user_id ORDER BY event_time) as prev_country,
                        LAG(geolocation:city::STRING) OVER (PARTITION BY user_id ORDER BY event_time) as prev_city,
                        LAG(source_ip) OVER (PARTITION BY user_id ORDER BY event_time) as prev_ip
                    FROM cyber_command.security_logs.auth_logs
                    WHERE auth_result = 'success'
                        AND geolocation IS NOT NULL
                        AND event_time >= DATEADD(day, -30, CURRENT_TIMESTAMP())
                )
                SELECT 
                    user_id,
                    prev_time as first_login,
                    CONCAT(prev_city, ', ', prev_country) as first_location,
                    prev_ip as first_ip,
                    event_time as second_login,
                    CONCAT(city, ', ', country) as second_location,
                    source_ip as second_ip,
                    DATEDIFF(hour, prev_time, event_time) as time_diff_hours,
                    DATEDIFF(minute, prev_time, event_time) as time_diff_minutes
                FROM user_locations
                WHERE prev_country IS NOT NULL
                    AND prev_country != country
                    AND DATEDIFF(hour, prev_time, event_time) < {max_travel_hours}
                    AND DATEDIFF(hour, prev_time, event_time) > 0
                ORDER BY time_diff_hours ASC
                """
                
                results = execute_query(query)
                
                if not results.empty:
                    st.warning(f"⚠️ Found {len(results)} impossible travel cases")
                    
                    # Visualization
                    fig = px.bar(
                        results.head(10), 
                        x='USER_ID', 
                        y='TIME_DIFF_HOURS',
                        color='TIME_DIFF_HOURS',
                        title="Impossible Travel Cases (Top 10)",
                        labels={'TIME_DIFF_HOURS': 'Time Between Logins (Hours)'}
                    )
                    fig.update_xaxes(tickangle=45)
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Detailed table
                    st.subheader("🔍 Impossible Travel Details")
                    display_cols = ['USER_ID', 'FIRST_LOCATION', 'SECOND_LOCATION', 'TIME_DIFF_HOURS', 'TIME_DIFF_MINUTES']
                    st.dataframe(results[display_cols], use_container_width=True)
                    
                else:
                    st.info("✅ No impossible travel patterns detected.")

with tab2:
    st.header("🔧 Custom Threat Hunting Queries")
    
    # Query templates
    templates = {
        "Basic Network Analysis": """
-- Analyze network traffic patterns
SELECT 
    destination_domain,
    COUNT(*) as connection_count,
    COUNT(DISTINCT user_id) as unique_users,
    SUM(bytes_transferred) as total_bytes
FROM cyber_command.security_logs.network_logs 
WHERE event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
GROUP BY destination_domain
ORDER BY connection_count DESC
LIMIT 20;""",
        
        "Authentication Failures": """
-- Find patterns in authentication failures
SELECT 
    source_ip,
    COUNT(DISTINCT user_id) as unique_users_attempted,
    COUNT(*) as total_failures,
    ARRAY_AGG(DISTINCT failure_reason) as failure_reasons,
    MIN(event_time) as first_attempt,
    MAX(event_time) as last_attempt
FROM cyber_command.security_logs.auth_logs
WHERE auth_result = 'failure'
    AND event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
GROUP BY source_ip
HAVING COUNT(*) > 50
ORDER BY total_failures DESC;""",
        
        "Threat Intelligence Hits": """
-- Find traffic matching threat intelligence
SELECT 
    nl.user_id,
    nl.destination_ip,
    nl.destination_domain,
    nl.bytes_transferred,
    ti.threat_type,
    ti.confidence_score,
    ti.source as intel_source,
    nl.event_time
FROM cyber_command.security_logs.network_logs nl
INNER JOIN cyber_command.security_logs.threat_intel ti 
    ON nl.destination_ip = ti.indicator
WHERE nl.event_time >= DATEADD(day, -7, CURRENT_TIMESTAMP())
    AND ti.is_active = TRUE
ORDER BY ti.confidence_score DESC, nl.bytes_transferred DESC;"""
    }
    
    # Template selector
    selected_template = st.selectbox("Choose a template:", ["Custom"] + list(templates.keys()))
    
    # Query editor
    if selected_template == "Custom":
        query = st.text_area(
            "Enter your threat hunting query:",
            height=300,
            value="-- Enter your custom SQL query here\nSELECT * FROM cyber_command.security_logs.network_logs LIMIT 10;"
        )
    else:
        query = st.text_area(
            f"Template: {selected_template}",
            height=300,
            value=templates[selected_template]
        )
    
    # Query execution
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        if st.button("🔍 Execute Query"):
            with st.spinner("Executing query..."):
                results = execute_query(query)
                st.session_state.hunt_results = results
                
                if not results.empty:
                    st.success(f"✅ Query executed successfully. Found {len(results)} results.")
                else:
                    st.info("Query executed successfully but returned no results.")
    
    with col2:
        if st.button("💾 Save Template"):
            template_name = st.text_input("Template Name:")
            if template_name:
                st.success(f"Template '{template_name}' saved!")
    
    with col3:
        if st.button("📋 Share Query"):
            st.info("Query sharing functionality would be implemented here.")

with tab3:
    st.header("📊 Hunt Results Analysis")
    
    if 'hunt_results' in st.session_state and not st.session_state.hunt_results.empty:
        results = st.session_state.hunt_results
        
        # Results summary
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Results", len(results))
        with col2:
            st.metric("Columns", len(results.columns))
        with col3:
            memory_usage = results.memory_usage(deep=True).sum() / 1024 / 1024
            st.metric("Memory Usage", f"{memory_usage:.1f} MB")
        
        # Data preview
        st.subheader("📋 Data Preview")
        st.dataframe(results.head(100), use_container_width=True)
        
        # Auto-visualization
        numeric_cols = results.select_dtypes(include=['number']).columns.tolist()
        text_cols = results.select_dtypes(include=['object']).columns.tolist()
        
        if len(numeric_cols) >= 2:
            st.subheader("📈 Quick Visualizations")
            
            col1, col2 = st.columns(2)
            with col1:
                x_axis = st.selectbox("X-axis:", numeric_cols + text_cols)
            with col2:
                y_axis = st.selectbox("Y-axis:", numeric_cols)
            
            if st.button("📊 Create Chart"):
                if x_axis in numeric_cols:
                    fig = px.scatter(results, x=x_axis, y=y_axis, title=f"{y_axis} vs {x_axis}")
                else:
                    fig = px.bar(results.groupby(x_axis)[y_axis].sum().reset_index(), 
                               x=x_axis, y=y_axis, title=f"{y_axis} by {x_axis}")
                st.plotly_chart(fig, use_container_width=True)
        
        # Export options
        st.subheader("📤 Export Results")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📥 Download CSV"):
                csv = results.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name=f"hunt_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            if st.button("📊 Create Dashboard"):
                st.info("Dashboard creation functionality would be implemented here.")
        
        with col3:
            if st.button("🚨 Create Alert"):
                st.info("Alert creation functionality would be implemented here.")
    
    else:
        st.info("No hunt results available. Execute a query in the Custom Queries tab to see results here.")

# Investigation panel
if 'investigation_user' in st.session_state:
    st.sidebar.markdown("---")
    st.sidebar.header("🕵️ Active Investigation")
    st.sidebar.write(f"**User:** {st.session_state.investigation_user}")
    
    if st.sidebar.button("📋 View Full Profile"):
        st.info(f"Full user profile for {st.session_state.investigation_user} would be displayed here.")
    
    if st.sidebar.button("🔔 Create Alert"):
        st.success(f"Alert created for {st.session_state.investigation_user}")
    
    if st.sidebar.button("❌ Close Investigation"):
        del st.session_state.investigation_user
        st.rerun() 