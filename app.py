"""
CyberShield AI Platform - Main Application Entry Point

This is the central Streamlit application that orchestrates all cybersecurity modules.
It provides a unified interface for threat detection, incident management, and security operations.

Key Features:
- Adaptive UI that changes colors based on threat levels
- Real-time security monitoring and analytics  
- AI-powered threat detection and response
- Gamified security awareness training
- Comprehensive incident management workflows
"""

# Core libraries for data science and web interface
import streamlit as st          # Web application framework
import pandas as pd             # Data manipulation and analysis
import numpy as np              # Numerical computing
import plotly.express as px     # Statistical visualization
import plotly.graph_objects as go  # Advanced plotting
from datetime import datetime, timedelta  # Date/time handling
import time                     # Time utilities for real-time updates

# Import cybersecurity modules - each handles a specific security domain
from modules import threat_detection, anomaly_detection, network_analysis
from modules import user_behavior, incident_management, threat_intelligence, wiz_integration, threat_timeline, security_awareness, security_chatbot, deep_learning_detection

# Import utility modules for shared infrastructure and UI components
from utils import data_processor, alerts, ml_models, rule_engine, database, ui_themes, security_validator

# Configure Streamlit page with cybersecurity branding and optimal layout
st.set_page_config(
    page_title="CyberShield AI Platform",  # Browser tab title
    page_icon="🛡️",                        # Shield icon representing security
    layout="wide",                          # Use full screen width for dashboards
    initial_sidebar_state="expanded"        # Start with sidebar open for navigation
)

# Initialize session state variables to maintain application state across page interactions
# Session state persists user settings and system status throughout the browser session
if 'alerts_enabled' not in st.session_state:
    st.session_state.alerts_enabled = True  # Enable real-time security alerts by default

if 'last_update' not in st.session_state:
    st.session_state.last_update = datetime.now()  # Track when data was last refreshed

if 'db_initialized' not in st.session_state:
    st.session_state.db_initialized = False  # Flag to ensure database setup runs only once

# Initialize database connection and populate with security data on first run
# This creates the PostgreSQL schema and adds sample security events for demonstration
if not st.session_state.db_initialized:
    try:
        # Set up database tables and load initial security data (alerts, incidents, IOCs)
        database.initialize_sample_data()
        st.session_state.db_initialized = True  # Mark as successfully initialized
    except Exception as e:
        # Graceful degradation if database connection fails
        st.error(f"Database initialization error: {str(e)}")
        st.info("The platform will run with limited functionality without database connectivity.")

def main():
    """
    Main application function that handles the user interface and navigation.
    
    This function:
    1. Sets up the adaptive theme system that changes colors based on threat levels
    2. Creates the main header and navigation
    3. Routes users to different security modules based on their selection
    4. Displays real-time threat status indicators
    """
    
    # Initialize the adaptive theme system that changes UI colors based on current threat level
    # Green = Low threat, Orange = Moderate, Red = High, Dark Red = Critical
    theme_manager = ui_themes.apply_adaptive_theme()
    
    # Main application header with security branding
    st.title("🛡️ CyberShield AI Platform")
    st.markdown("AI-Powered Cybersecurity Monitoring and Threat Detection")
    
    # Display current threat level with color-coded indicator in the main area
    # This gives users immediate visual feedback about the security status
    ui_themes.show_threat_status()
    
    # Create sidebar navigation menu for accessing different security modules
    st.sidebar.title("Navigation")
    
    # Show threat status indicator in sidebar for constant visibility
    theme_manager.show_sidebar_threat_status()
    
    # Module selection dropdown - organizes all security functionality into logical categories
    page = st.sidebar.selectbox(
        "Select Module",
        [
            "Dashboard",                    # Main overview with key metrics and alerts
            "Threat Detection",             # AI-powered threat identification and analysis
            "Deep Learning Detection",      # Advanced ML models (Neural Networks, SVM, etc.)
            "Threat Timeline",              # Interactive timeline visualization with micro-interactions
            "Anomaly Analysis",             # Statistical and ML-based anomaly detection
            "Network Analysis",             # Network traffic monitoring and geographic analysis
            "User Behavior Analytics",      # Insider threat detection through behavioral analysis
            "Incident Management",          # Complete incident lifecycle management
            "Threat Intelligence",          # IOC tracking and threat feed integration
            "Security Awareness",           # Gamified training platform with achievements
            "AI Security Assistant",        # OpenAI-powered security guidance chatbot
            "Wiz Integration",              # Cloud security platform integration
            "System Settings"               # Platform configuration and preferences
        ]
    )
    
    # Route user to selected module - each module is self-contained with its own interface
    # This modular approach allows independent development and testing of each security domain
    
    if page == "Dashboard":
        # Main overview dashboard with real-time security metrics and status
        dashboard_overview()
        
    elif page == "Threat Detection":
        # Core AI-powered threat identification with confidence scoring
        threat_detection.show_threat_detection()
        
    elif page == "Deep Learning Detection":
        # Advanced machine learning models for sophisticated threat detection
        # Includes Neural Networks, Isolation Forest, Random Forest, and SVM models
        deep_learning_detection.show_deep_learning_detection()
        
    elif page == "Threat Timeline":
        # Interactive timeline with smooth animations and micro-interactions
        # Provides chronological view of security events with filtering capabilities
        threat_timeline.show_threat_timeline()
        
    elif page == "Anomaly Analysis":
        # Statistical and machine learning based anomaly detection
        # Identifies unusual patterns that may indicate security threats
        anomaly_detection.show_anomaly_analysis()
        
    elif page == "Network Analysis":
        # Network traffic monitoring, analysis, and geographic threat mapping
        network_analysis.show_network_analysis()
    elif page == "User Behavior Analytics":
        # Insider threat detection through behavioral pattern analysis
        # Monitors user activities to identify potential internal security risks
        user_behavior.show_user_behavior()
        
    elif page == "Incident Management":
        # Complete incident lifecycle management with automated workflows
        # Handles creation, tracking, escalation, and resolution of security incidents
        incident_management.show_incident_management()
        
    elif page == "Threat Intelligence":
        # IOC (Indicators of Compromise) tracking and threat feed integration
        # Aggregates intelligence from multiple sources for proactive threat hunting
        threat_intelligence.show_threat_intelligence()
        
    elif page == "Security Awareness":
        # Gamified security training platform with achievements and leaderboards
        # Engages users through interactive challenges and progress tracking
        security_awareness.show_security_awareness()
        
    elif page == "AI Security Assistant":
        # OpenAI-powered security guidance chatbot with contextual recommendations
        # Provides intelligent assistance for security questions and incident response
        security_chatbot.show_security_chatbot()
        
    elif page == "Wiz Integration":
        # Cloud security platform integration for comprehensive coverage
        # Connects with Wiz to monitor cloud infrastructure and compliance
        wiz_integration.show_wiz_integration()
        
    elif page == "System Settings":
        # Platform configuration, preferences, and administrative functions
        system_settings()

def dashboard_overview():
    """
    Main dashboard displaying real-time security metrics and system status.
    
    This central command center provides:
    - Key performance indicators (KPIs) for security operations
    - Real-time threat level monitoring
    - Active incident tracking
    - System health and performance metrics
    - Quick access to critical alerts and recent activity
    """
    
    # Auto-refresh functionality for real-time monitoring
    # Allows dashboard to automatically update every 30 seconds for live data
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)
    if auto_refresh:
        time.sleep(30)  # Wait 30 seconds before refreshing
        st.rerun()      # Trigger Streamlit page refresh
    
    # Create a 4-column layout for key security metrics
    # This provides at-a-glance visibility into critical security indicators
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
