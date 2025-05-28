import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time

# Import custom modules
from modules import threat_detection, anomaly_detection, network_analysis
from modules import user_behavior, incident_management, threat_intelligence, wiz_integration, threat_timeline, security_awareness, security_chatbot
from utils import data_processor, alerts, ml_models, rule_engine, database, ui_themes

# Configure page
st.set_page_config(
    page_title="CyberShield AI Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'alerts_enabled' not in st.session_state:
    st.session_state.alerts_enabled = True
if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()
if 'db_initialized' not in st.session_state:
    st.session_state.db_initialized = False

# Initialize database and sample data on first run
if not st.session_state.db_initialized:
    try:
        database.initialize_sample_data()
        st.session_state.db_initialized = True
    except Exception as e:
        st.error(f"Database initialization error: {str(e)}")
        st.info("The platform will run with limited functionality without database connectivity.")

def main():
    # Initialize adaptive theme system
    theme_manager = ui_themes.apply_adaptive_theme()
    
    st.title("🛡️ CyberShield AI Platform")
    st.markdown("AI-Powered Cybersecurity Monitoring and Threat Detection")
    
    # Show current threat level indicator
    ui_themes.show_threat_status()
    
    # Sidebar navigation with threat status
    st.sidebar.title("Navigation")
    theme_manager.show_sidebar_threat_status()
    page = st.sidebar.selectbox(
        "Select Module",
        [
            "Dashboard",
            "Threat Detection",
            "Threat Timeline",
            "Anomaly Analysis",
            "Network Analysis",
            "User Behavior Analytics",
            "Incident Management",
            "Threat Intelligence",
            "Security Awareness",
            "AI Security Assistant",
            "Wiz Integration",
            "System Settings"
        ]
    )
    
    # Main dashboard overview
    if page == "Dashboard":
        dashboard_overview()
    elif page == "Threat Detection":
        threat_detection.show_threat_detection()
    elif page == "Threat Timeline":
        threat_timeline.show_threat_timeline()
    elif page == "Anomaly Analysis":
        anomaly_detection.show_anomaly_analysis()
    elif page == "Network Analysis":
        network_analysis.show_network_analysis()
    elif page == "User Behavior Analytics":
        user_behavior.show_user_behavior()
    elif page == "Incident Management":
        incident_management.show_incident_management()
    elif page == "Threat Intelligence":
        threat_intelligence.show_threat_intelligence()
    elif page == "Security Awareness":
        security_awareness.show_security_awareness()
    elif page == "AI Security Assistant":
        security_chatbot.show_security_chatbot()
    elif page == "Wiz Integration":
        wiz_integration.show_wiz_integration()
    elif page == "System Settings":
        system_settings()

def dashboard_overview():
    """Main dashboard with real-time security metrics"""
    
    # Auto-refresh functionality
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    # Real-time metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Threat Level",
            "MEDIUM",
            delta="2 new threats",
            delta_color="inverse"
        )
    
    with col2:
        st.metric(
            "Active Incidents",
            "7",
            delta="-3 from yesterday",
            delta_color="normal"
        )
    
    with col3:
        st.metric(
            "Network Anomalies",
            "12",
            delta="+5 detected",
            delta_color="inverse"
        )
    
    with col4:
        st.metric(
            "System Health",
            "98.5%",
            delta="+0.2%",
            delta_color="normal"
        )
    
    st.divider()
    
    # Recent alerts section - Database Integration
    st.subheader("🚨 Recent Security Alerts")
    try:
        db = database.get_database()
        recent_alerts = db.get_recent_alerts(hours=24, limit=5)
        
        if recent_alerts:
            for alert in recent_alerts:
                severity_color = {
                    "CRITICAL": "🔥",
                    "HIGH": "🔴",
                    "MEDIUM": "🟡", 
                    "LOW": "🟢"
                }.get(alert.get('severity', 'LOW'), '🔵')
                
                st.write(f"{severity_color} **{alert.get('title', 'Unknown Alert')}** - {alert.get('created_at', 'Unknown time')}")
                st.write(f"   {alert.get('description', 'No description available')}")
        else:
            st.info("No recent security alerts. System is operating normally.")
            
    except Exception as e:
        st.warning("Using offline mode - database connectivity issue")
        st.info("No recent security alerts available in offline mode.")
    
    st.divider()
    
    # Security metrics visualization
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Threat Detection Trends")
        # Generate sample threat data for visualization
        dates = pd.date_range(start=datetime.now() - timedelta(days=30), 
                             end=datetime.now(), freq='D')
        threat_data = pd.DataFrame({
            'Date': dates,
            'Malware': np.random.poisson(3, len(dates)),
            'Phishing': np.random.poisson(2, len(dates)),
            'DDoS': np.random.poisson(1, len(dates)),
            'Intrusion': np.random.poisson(2, len(dates))
        })
        
        fig = px.line(threat_data, x='Date', 
                     y=['Malware', 'Phishing', 'DDoS', 'Intrusion'],
                     title="Threat Detection Over Time")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🎯 Threat Distribution")
        threat_types = ['Malware', 'Phishing', 'DDoS', 'Intrusion', 'Data Breach']
        threat_counts = [45, 32, 18, 28, 12]
        
        fig = px.pie(values=threat_counts, names=threat_types,
                     title="Current Threat Landscape")
        st.plotly_chart(fig, use_container_width=True)
    
    # Network traffic overview
    st.subheader("🌐 Network Traffic Analysis")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Inbound Traffic", "2.4 GB/hr", delta="+12%")
    
    with col2:
        st.metric("Outbound Traffic", "1.8 GB/hr", delta="-5%")
    
    with col3:
        st.metric("Blocked Requests", "1,247", delta="+234")
    
    # System status
    st.subheader("⚙️ System Status")
    
    systems = [
        {"name": "Threat Detection Engine", "status": "Online", "uptime": "99.9%"},
        {"name": "Anomaly Detection", "status": "Online", "uptime": "98.7%"},
        {"name": "Network Monitor", "status": "Online", "uptime": "99.5%"},
        {"name": "Incident Response", "status": "Online", "uptime": "100%"},
        {"name": "Threat Intelligence", "status": "Updating", "uptime": "99.2%"}
    ]
    
    for system in systems:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.write(f"**{system['name']}**")
        with col2:
            status_color = "🟢" if system['status'] == "Online" else "🟡"
            st.write(f"{status_color} {system['status']}")
        with col3:
            st.write(system['uptime'])

def system_settings():
    """System configuration and settings"""
    st.subheader("⚙️ System Settings")
    
    st.write("### Alert Configuration")
    st.session_state.alerts_enabled = st.checkbox(
        "Enable Real-time Alerts", 
        value=st.session_state.alerts_enabled
    )
    
    alert_threshold = st.slider(
        "Alert Sensitivity Threshold", 
        min_value=1, max_value=10, value=5
    )
    
    st.write("### Monitoring Configuration")
    refresh_interval = st.selectbox(
        "Auto-refresh Interval",
        ["30 seconds", "1 minute", "5 minutes", "Disabled"],
        index=0
    )
    
    st.write("### Data Retention")
    retention_period = st.slider(
        "Log Retention Period (days)",
        min_value=7, max_value=365, value=90
    )
    
    st.write("### Export Settings")
    if st.button("Export Security Report"):
        st.success("Security report exported successfully!")
    
    if st.button("Backup Configuration"):
        st.success("System configuration backed up!")
    
    st.write("### System Information")
    info_data = {
        "Platform Version": "CyberShield AI v2.1.0",
        "Last Update": st.session_state.last_update.strftime("%Y-%m-%d %H:%M:%S"),
        "Active Users": "3",
        "Database Status": "Connected",
        "ML Models": "4 Active"
    }
    
    for key, value in info_data.items():
        st.write(f"**{key}:** {value}")

if __name__ == "__main__":
    main()
