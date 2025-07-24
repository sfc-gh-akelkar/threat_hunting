"""
Security Analytics Dashboard
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime, timedelta

st.set_page_config(page_title="Security Analytics", page_icon="📊")

st.title("📊 Security Analytics Dashboard")

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

# Analytics filters
st.sidebar.header("🔧 Analytics Filters")
time_window = st.sidebar.selectbox(
    "Time Window:",
    ["Last 24 hours", "Last 7 days", "Last 30 days", "Last 90 days"]
)

include_internal = st.sidebar.checkbox("Include Internal Traffic", value=True)
min_threat_score = st.sidebar.slider("Minimum Threat Score", 0.0, 1.0, 0.0, 0.1)

# Map time windows to SQL
time_filters = {
    "Last 24 hours": "DATEADD(day, -1, CURRENT_TIMESTAMP())",
    "Last 7 days": "DATEADD(day, -7, CURRENT_TIMESTAMP())",
    "Last 30 days": "DATEADD(day, -30, CURRENT_TIMESTAMP())",
    "Last 90 days": "DATEADD(day, -90, CURRENT_TIMESTAMP())"
}

time_filter = time_filters[time_window]

# Main analytics tabs
overview_tab, network_tab, users_tab, threats_tab, compliance_tab = st.tabs([
    "🏠 Overview", "🌐 Network", "👥 Users", "🚨 Threats", "📋 Compliance"
])

with overview_tab:
    st.header("Security Overview")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Total events
    total_events = execute_query(f"""
        SELECT COUNT(*) as event_count
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
    """)
    
    # High-risk events
    high_risk_events = execute_query(f"""
        SELECT COUNT(*) as high_risk_count
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        AND threat_score > 0.7
    """)
    
    # Unique users
    unique_users = execute_query(f"""
        SELECT COUNT(DISTINCT user_id) as user_count
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
    """)
    
    # Data transferred
    data_transferred = execute_query(f"""
        SELECT ROUND(SUM(bytes_transferred)/1024/1024/1024, 2) as gb_transferred
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
    """)
    
    with col1:
        total = total_events['EVENT_COUNT'].iloc[0] if not total_events.empty else 0
        st.metric("📊 Total Events", f"{total:,}")
    
    with col2:
        high_risk = high_risk_events['HIGH_RISK_COUNT'].iloc[0] if not high_risk_events.empty else 0
        st.metric("🚨 High-Risk Events", f"{high_risk:,}")
    
    with col3:
        users = unique_users['USER_COUNT'].iloc[0] if not unique_users.empty else 0
        st.metric("👥 Active Users", f"{users:,}")
    
    with col4:
        data_gb = data_transferred['GB_TRANSFERRED'].iloc[0] if not data_transferred.empty else 0
        st.metric("📡 Data Transferred", f"{data_gb:.1f} GB")
    
    # Timeline analysis
    st.subheader("📈 Security Events Timeline")
    
    timeline_data = execute_query(f"""
        SELECT 
            DATE_TRUNC('hour', event_time) as hour,
            COUNT(*) as total_events,
            COUNT(CASE WHEN threat_score > 0.7 THEN 1 END) as high_threat_events,
            AVG(threat_score) as avg_threat_score,
            SUM(bytes_transferred) as total_bytes
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        GROUP BY DATE_TRUNC('hour', event_time)
        ORDER BY hour
    """)
    
    if not timeline_data.empty:
        fig = make_subplots(
            rows=2, cols=1,
            subplot_titles=('Event Volume', 'Threat Score & Data Transfer'),
            specs=[[{"secondary_y": True}], [{"secondary_y": True}]]
        )
        
        # Event volume
        fig.add_trace(
            go.Bar(x=timeline_data['HOUR'], y=timeline_data['TOTAL_EVENTS'], 
                   name="Total Events", marker_color='lightblue'),
            row=1, col=1
        )
        
        fig.add_trace(
            go.Bar(x=timeline_data['HOUR'], y=timeline_data['HIGH_THREAT_EVENTS'], 
                   name="High Threat Events", marker_color='red'),
            row=1, col=1
        )
        
        # Threat score trend
        fig.add_trace(
            go.Scatter(x=timeline_data['HOUR'], y=timeline_data['AVG_THREAT_SCORE'], 
                      name="Avg Threat Score", line=dict(color='orange', width=2)),
            row=2, col=1
        )
        
        # Data transfer
        fig.add_trace(
            go.Scatter(x=timeline_data['HOUR'], y=timeline_data['TOTAL_BYTES'], 
                      name="Data Transfer", line=dict(color='green', width=2)),
            row=2, col=1, secondary_y=True
        )
        
        fig.update_layout(height=600, title=f"Security Metrics - {time_window}")
        st.plotly_chart(fig, use_container_width=True)
    
    # Risk distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Risk Score Distribution")
        risk_distribution = execute_query(f"""
            SELECT 
                CASE 
                    WHEN threat_score >= 0.8 THEN 'Critical (0.8-1.0)'
                    WHEN threat_score >= 0.6 THEN 'High (0.6-0.8)'
                    WHEN threat_score >= 0.4 THEN 'Medium (0.4-0.6)'
                    WHEN threat_score >= 0.2 THEN 'Low (0.2-0.4)'
                    ELSE 'Minimal (0.0-0.2)'
                END as risk_category,
                COUNT(*) as event_count
            FROM cyber_command.security_logs.network_logs 
            WHERE event_time >= {time_filter}
            GROUP BY risk_category
            ORDER BY 
                CASE 
                    WHEN threat_score >= 0.8 THEN 1
                    WHEN threat_score >= 0.6 THEN 2
                    WHEN threat_score >= 0.4 THEN 3
                    WHEN threat_score >= 0.2 THEN 4
                    ELSE 5
                END
        """)
        
        if not risk_distribution.empty:
            colors = ['#ff4444', '#ff8800', '#ffaa00', '#88aa44', '#44aa44']
            fig = px.pie(risk_distribution, values='EVENT_COUNT', names='RISK_CATEGORY',
                        color_discrete_sequence=colors)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🌐 Top Destination Domains")
        top_domains = execute_query(f"""
            SELECT 
                destination_domain,
                COUNT(*) as connection_count,
                COUNT(DISTINCT user_id) as unique_users,
                AVG(threat_score) as avg_threat_score
            FROM cyber_command.security_logs.network_logs 
            WHERE event_time >= {time_filter}
            AND destination_domain IS NOT NULL
            GROUP BY destination_domain
            ORDER BY connection_count DESC
            LIMIT 10
        """)
        
        if not top_domains.empty:
            fig = px.bar(top_domains, x='CONNECTION_COUNT', y='DESTINATION_DOMAIN',
                        color='AVG_THREAT_SCORE', orientation='h',
                        color_continuous_scale='reds')
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

with network_tab:
    st.header("🌐 Network Traffic Analysis")
    
    # Protocol analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Protocol Distribution")
        protocol_data = execute_query(f"""
            SELECT 
                protocol,
                COUNT(*) as event_count,
                SUM(bytes_transferred) as total_bytes,
                AVG(threat_score) as avg_threat_score
            FROM cyber_command.security_logs.network_logs 
            WHERE event_time >= {time_filter}
            GROUP BY protocol
            ORDER BY event_count DESC
        """)
        
        if not protocol_data.empty:
            fig = px.pie(protocol_data, values='EVENT_COUNT', names='PROTOCOL',
                        title="Events by Protocol")
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("💾 Data Transfer by Protocol")
        if not protocol_data.empty:
            protocol_data['TOTAL_GB'] = protocol_data['TOTAL_BYTES'] / (1024**3)
            fig = px.bar(protocol_data, x='PROTOCOL', y='TOTAL_GB',
                        color='AVG_THREAT_SCORE', title="Data Transfer (GB)")
            st.plotly_chart(fig, use_container_width=True)
    
    # Port analysis
    st.subheader("🔌 Port Activity Analysis")
    port_data = execute_query(f"""
        SELECT 
            destination_port,
            COUNT(*) as connection_count,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(DISTINCT source_ip) as unique_sources,
            AVG(threat_score) as avg_threat_score
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        AND destination_port IS NOT NULL
        GROUP BY destination_port
        ORDER BY connection_count DESC
        LIMIT 20
    """)
    
    if not port_data.empty:
        fig = px.scatter(port_data, x='DESTINATION_PORT', y='CONNECTION_COUNT',
                        size='UNIQUE_USERS', color='AVG_THREAT_SCORE',
                        hover_data=['UNIQUE_SOURCES'],
                        title="Port Activity (Size = Unique Users, Color = Avg Threat Score)")
        st.plotly_chart(fig, use_container_width=True)
        
        # Port details table
        st.subheader("📋 Port Details")
        st.dataframe(port_data, use_container_width=True)
    
    # Geographic analysis
    st.subheader("🗺️ Geographic Traffic Analysis")
    geo_data = execute_query(f"""
        SELECT 
            geolocation:country::STRING as country,
            COUNT(*) as connection_count,
            COUNT(DISTINCT user_id) as unique_users,
            AVG(threat_score) as avg_threat_score,
            SUM(bytes_transferred) as total_bytes
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        AND geolocation IS NOT NULL
        GROUP BY country
        ORDER BY connection_count DESC
        LIMIT 15
    """)
    
    if not geo_data.empty:
        geo_data['TOTAL_GB'] = geo_data['TOTAL_BYTES'] / (1024**3)
        
        col1, col2 = st.columns(2)
        with col1:
            fig = px.bar(geo_data.head(10), x='COUNTRY', y='CONNECTION_COUNT',
                        color='AVG_THREAT_SCORE', title="Connections by Country")
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.scatter(geo_data, x='UNIQUE_USERS', y='TOTAL_GB',
                           size='CONNECTION_COUNT', color='AVG_THREAT_SCORE',
                           hover_data=['COUNTRY'],
                           title="Data Transfer vs Users by Country")
            st.plotly_chart(fig, use_container_width=True)

with users_tab:
    st.header("👥 User Behavior Analysis")
    
    # Top active users
    st.subheader("🔝 Most Active Users")
    user_activity = execute_query(f"""
        SELECT 
            user_id,
            COUNT(*) as total_events,
            SUM(bytes_transferred) as total_bytes,
            COUNT(DISTINCT destination_ip) as unique_destinations,
            COUNT(DISTINCT destination_domain) as unique_domains,
            AVG(threat_score) as avg_threat_score,
            MAX(event_time) as last_activity
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        GROUP BY user_id
        ORDER BY total_events DESC
        LIMIT 20
    """)
    
    if not user_activity.empty:
        user_activity['TOTAL_GB'] = user_activity['TOTAL_BYTES'] / (1024**3)
        
        # User activity visualization
        fig = px.scatter(user_activity, x='UNIQUE_DESTINATIONS', y='TOTAL_GB',
                        size='TOTAL_EVENTS', color='AVG_THREAT_SCORE',
                        hover_data=['USER_ID', 'UNIQUE_DOMAINS'],
                        title="User Activity Patterns")
        st.plotly_chart(fig, use_container_width=True)
        
        # User activity table
        display_cols = ['USER_ID', 'TOTAL_EVENTS', 'TOTAL_GB', 'UNIQUE_DESTINATIONS', 
                       'UNIQUE_DOMAINS', 'AVG_THREAT_SCORE', 'LAST_ACTIVITY']
        st.dataframe(user_activity[display_cols], use_container_width=True)
    
    # User risk analysis
    st.subheader("⚠️ High-Risk Users")
    high_risk_users = execute_query(f"""
        SELECT 
            user_id,
            COUNT(*) as high_risk_events,
            AVG(threat_score) as avg_threat_score,
            SUM(bytes_transferred) as total_bytes,
            COUNT(DISTINCT destination_ip) as unique_destinations,
            MAX(event_time) as last_high_risk_activity
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        AND threat_score > 0.6
        GROUP BY user_id
        HAVING COUNT(*) > 5
        ORDER BY avg_threat_score DESC, high_risk_events DESC
        LIMIT 10
    """)
    
    if not high_risk_users.empty:
        high_risk_users['TOTAL_MB'] = high_risk_users['TOTAL_BYTES'] / (1024**2)
        
        fig = px.bar(high_risk_users, x='USER_ID', y='HIGH_RISK_EVENTS',
                    color='AVG_THREAT_SCORE', title="High-Risk Events by User")
        fig.update_xaxes(tickangle=45)
        st.plotly_chart(fig, use_container_width=True)
        
        # High-risk users table
        display_cols = ['USER_ID', 'HIGH_RISK_EVENTS', 'AVG_THREAT_SCORE', 'TOTAL_MB', 
                       'UNIQUE_DESTINATIONS', 'LAST_HIGH_RISK_ACTIVITY']
        st.dataframe(high_risk_users[display_cols], use_container_width=True)
    else:
        st.info("✅ No high-risk users identified in the selected time period.")

with threats_tab:
    st.header("🚨 Threat Intelligence Analysis")
    
    # Threat intelligence summary
    threat_summary = execute_query("""
        SELECT 
            threat_type,
            COUNT(*) as indicator_count,
            AVG(confidence_score) as avg_confidence,
            COUNT(CASE WHEN confidence_score > 0.8 THEN 1 END) as high_confidence_count
        FROM cyber_command.security_logs.threat_intel 
        WHERE is_active = TRUE
        GROUP BY threat_type
        ORDER BY indicator_count DESC
    """)
    
    if not threat_summary.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.bar(threat_summary, x='THREAT_TYPE', y='INDICATOR_COUNT',
                        color='AVG_CONFIDENCE', title="Threat Intelligence by Type")
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig = px.scatter(threat_summary, x='INDICATOR_COUNT', y='AVG_CONFIDENCE',
                           size='HIGH_CONFIDENCE_COUNT', hover_data=['THREAT_TYPE'],
                           title="Threat Intelligence Quality")
            st.plotly_chart(fig, use_container_width=True)
    
    # Threat matches in network traffic
    st.subheader("🎯 Threat Intelligence Matches")
    threat_matches = execute_query(f"""
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
        WHERE nl.event_time >= {time_filter}
            AND ti.is_active = TRUE
        ORDER BY ti.confidence_score DESC, nl.bytes_transferred DESC
        LIMIT 50
    """)
    
    if not threat_matches.empty:
        # Threat matches over time
        threat_matches['DATE'] = pd.to_datetime(threat_matches['EVENT_TIME']).dt.date
        daily_threats = threat_matches.groupby(['DATE', 'THREAT_TYPE']).size().reset_index(name='COUNT')
        
        fig = px.bar(daily_threats, x='DATE', y='COUNT', color='THREAT_TYPE',
                    title="Threat Intelligence Matches Over Time")
        st.plotly_chart(fig, use_container_width=True)
        
        # Threat matches table
        st.subheader("📋 Recent Threat Matches")
        threat_matches['BYTES_MB'] = threat_matches['BYTES_TRANSFERRED'] / (1024**2)
        display_cols = ['USER_ID', 'DESTINATION_IP', 'DESTINATION_DOMAIN', 'THREAT_TYPE', 
                       'CONFIDENCE_SCORE', 'BYTES_MB', 'EVENT_TIME']
        st.dataframe(threat_matches[display_cols], use_container_width=True)
    else:
        st.info("✅ No threat intelligence matches found in the selected time period.")

with compliance_tab:
    st.header("📋 Compliance & Governance")
    
    # Data handling metrics
    st.subheader("📊 Data Handling Metrics")
    
    col1, col2, col3 = st.columns(3)
    
    # Total data processed
    with col1:
        total_data = execute_query(f"""
            SELECT ROUND(SUM(bytes_transferred)/1024/1024/1024, 2) as total_gb
            FROM cyber_command.security_logs.network_logs 
            WHERE event_time >= {time_filter}
        """)
        gb_processed = total_data['TOTAL_GB'].iloc[0] if not total_data.empty else 0
        st.metric("📊 Data Processed", f"{gb_processed:.1f} GB")
    
    # External transfers
    with col2:
        external_data = execute_query(f"""
            SELECT ROUND(SUM(bytes_transferred)/1024/1024/1024, 2) as external_gb
            FROM cyber_command.security_logs.network_logs 
            WHERE event_time >= {time_filter}
            AND NOT (destination_ip LIKE '10.%' OR destination_ip LIKE '192.168.%' OR destination_ip LIKE '172.16.%')
        """)
        gb_external = external_data['EXTERNAL_GB'].iloc[0] if not external_data.empty else 0
        st.metric("🌐 External Transfers", f"{gb_external:.1f} GB")
    
    # Policy violations
    with col3:
        violations = execute_query(f"""
            SELECT COUNT(*) as violation_count
            FROM cyber_command.security_logs.network_logs 
            WHERE event_time >= {time_filter}
            AND (bytes_transferred > 100000000 OR threat_score > 0.8)
        """)
        violation_count = violations['VIOLATION_COUNT'].iloc[0] if not violations.empty else 0
        st.metric("⚠️ Policy Violations", violation_count)
    
    # Compliance reporting
    st.subheader("📈 Compliance Trends")
    
    compliance_trends = execute_query(f"""
        SELECT 
            DATE(event_time) as date,
            COUNT(*) as total_events,
            COUNT(CASE WHEN bytes_transferred > 100000000 THEN 1 END) as large_transfers,
            COUNT(CASE WHEN threat_score > 0.8 THEN 1 END) as high_risk_events,
            COUNT(CASE WHEN NOT (destination_ip LIKE '10.%' OR destination_ip LIKE '192.168.%' OR destination_ip LIKE '172.16.%') THEN 1 END) as external_connections
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        GROUP BY DATE(event_time)
        ORDER BY date
    """)
    
    if not compliance_trends.empty:
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(x=compliance_trends['DATE'], y=compliance_trends['LARGE_TRANSFERS'],
                                mode='lines+markers', name='Large Transfers (>100MB)'))
        fig.add_trace(go.Scatter(x=compliance_trends['DATE'], y=compliance_trends['HIGH_RISK_EVENTS'],
                                mode='lines+markers', name='High Risk Events'))
        fig.add_trace(go.Scatter(x=compliance_trends['DATE'], y=compliance_trends['EXTERNAL_CONNECTIONS'],
                                mode='lines+markers', name='External Connections'))
        
        fig.update_layout(title="Compliance Metrics Trends", height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # Audit trail
    st.subheader("🔍 Audit Trail Summary")
    audit_summary = execute_query(f"""
        SELECT 
            user_id,
            COUNT(*) as total_activities,
            COUNT(CASE WHEN bytes_transferred > 50000000 THEN 1 END) as large_file_activities,
            COUNT(DISTINCT destination_domain) as unique_domains_accessed,
            MAX(event_time) as last_activity
        FROM cyber_command.security_logs.network_logs 
        WHERE event_time >= {time_filter}
        GROUP BY user_id
        HAVING COUNT(CASE WHEN bytes_transferred > 50000000 THEN 1 END) > 0
        ORDER BY large_file_activities DESC
        LIMIT 20
    """)
    
    if not audit_summary.empty:
        st.dataframe(audit_summary, use_container_width=True)
    else:
        st.info("No significant file transfer activities requiring audit attention.")

# Export functionality
st.sidebar.markdown("---")
st.sidebar.header("📤 Export Options")

if st.sidebar.button("📊 Export Dashboard"):
    st.sidebar.info("Dashboard export functionality would be implemented here.")

if st.sidebar.button("📧 Schedule Report"):
    st.sidebar.info("Report scheduling functionality would be implemented here.")

# Refresh data
if st.sidebar.button("🔄 Refresh Data"):
    st.cache_data.clear()
    st.success("Data cache cleared. Dashboard will refresh with latest data.")
    st.rerun() 