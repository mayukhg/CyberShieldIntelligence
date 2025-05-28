"""
Core Threat Detection Module for CyberShield AI Platform

This module provides AI-powered threat identification and analysis capabilities.
It serves as the primary interface for security analysts to monitor, detect, and investigate
potential security threats across the network infrastructure.

Key Features:
- Real-time threat monitoring with live metrics
- AI-powered threat classification and scoring
- Interactive threat investigation workflows
- Automated threat response recommendations
- Integration with machine learning models for advanced detection
"""

import streamlit as st              # Web interface framework for security dashboards
import pandas as pd                 # Data manipulation for threat analysis
import numpy as np                  # Numerical computing for threat scoring algorithms
import plotly.express as px         # Statistical visualization for threat trends
import plotly.graph_objects as go   # Advanced plotting for threat correlation analysis
from datetime import datetime, timedelta  # Time handling for threat timeline analysis
from utils import ml_models, rule_engine   # Internal utilities for ML models and security rules

def show_threat_detection():
    """
    Main threat detection interface for security analysts.
    
    This function creates an interactive dashboard that provides:
    - Real-time threat metrics and status indicators
    - Threat detection controls and configuration options
    - Live threat feed with detailed analysis capabilities
    - Historical trend analysis and pattern recognition
    - Automated threat response and mitigation recommendations
    """
    # Main header with security-focused branding
    st.header("🔍 AI-Powered Threat Detection")
    
    # Create three-column layout for key threat metrics
    # These provide immediate visibility into current security status
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Active Threats", "14", delta="+3")
    with col2:
        st.metric("Threats Blocked", "127", delta="+12")
    with col3:
        st.metric("Risk Score", "7.2/10", delta="+0.8")
    
    st.divider()
    
    # Threat detection controls
    st.subheader("Detection Controls")
    
    col1, col2 = st.columns(2)
    
    with col1:
        detection_mode = st.selectbox(
            "Detection Mode",
            ["Real-time", "Batch Processing", "Deep Scan"]
        )
        
        sensitivity = st.slider(
            "Detection Sensitivity",
            min_value=1, max_value=10, value=7
        )
    
    with col2:
        scan_scope = st.multiselect(
            "Scan Scope",
            ["Network Traffic", "Email", "File System", "Web Traffic", "API Calls"],
            default=["Network Traffic", "Email"]
        )
        
        if st.button("Start Manual Scan"):
            with st.spinner("Scanning for threats..."):
                # Simulate threat scanning
                progress = st.progress(0)
                for i in range(100):
                    progress.progress(i + 1)
                st.success("Scan completed! 3 new threats detected.")
    
    # Current threats table
    st.subheader("🚨 Current Threats")
    
    # Generate realistic threat data
    threat_data = generate_threat_data()
    
    # Threat severity filter
    severity_filter = st.multiselect(
        "Filter by Severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )
    
    filtered_threats = threat_data[threat_data['Severity'].isin(severity_filter)]
    
    # Display threats with color coding
    for _, threat in filtered_threats.iterrows():
        severity_color = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }.get(threat['Severity'], "🔵")
        
        with st.expander(f"{severity_color} {threat['Type']} - {threat['Severity']} Priority"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Source:** {threat['Source']}")
                st.write(f"**Target:** {threat['Target']}")
                st.write(f"**Detection Time:** {threat['Detected']}")
            
            with col2:
                st.write(f"**Risk Score:** {threat['Risk_Score']}/10")
                st.write(f"**Status:** {threat['Status']}")
                st.write(f"**Action Required:** {threat['Action']}")
            
            st.write(f"**Description:** {threat['Description']}")
            
            # Action buttons
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button(f"Block {threat['Type']}", key=f"block_{threat.name}"):
                    st.success(f"Threat {threat['Type']} has been blocked!")
            
            with col2:
                if st.button(f"Investigate", key=f"investigate_{threat.name}"):
                    st.info(f"Investigation started for {threat['Type']}")
            
            with col3:
                if st.button(f"Mark as False Positive", key=f"false_{threat.name}"):
                    st.warning(f"Threat {threat['Type']} marked as false positive")
    
    # Threat analytics
    st.subheader("📊 Threat Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat timeline
        timeline_data = generate_threat_timeline()
        fig = px.scatter(timeline_data, x='Time', y='Severity_Numeric', 
                        color='Type', size='Risk_Score',
                        title="Threat Detection Timeline",
                        hover_data=['Source', 'Target'])
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Threat source analysis
        source_counts = threat_data['Source'].value_counts()
        fig = px.bar(x=source_counts.index, y=source_counts.values,
                     title="Threats by Source",
                     labels={'x': 'Source', 'y': 'Count'})
        st.plotly_chart(fig, use_container_width=True)
    
    # ML-based threat prediction
    st.subheader("🤖 AI Threat Prediction")
    
    prediction_results = ml_models.predict_threats()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Predicted Threats (24h)", prediction_results.get('next_24h', 'N/A'))
    
    with col2:
        st.metric("Risk Trend", prediction_results.get('trend', 'N/A'))
    
    with col3:
        st.metric("Confidence", f"{prediction_results.get('confidence', 0)}%")
    
    # Threat intelligence integration
    st.subheader("🌐 Threat Intelligence Feed")
    
    intel_data = get_threat_intelligence()
    
    for intel in intel_data[:3]:  # Show top 3 intelligence items
        st.info(f"**{intel['source']}:** {intel['description']}")

def generate_threat_data():
    """Generate realistic threat data for demonstration"""
    threat_types = ["Malware", "Phishing", "DDoS", "SQL Injection", "XSS", "Data Breach", "Ransomware"]
    severities = ["Critical", "High", "Medium", "Low"]
    sources = ["External IP", "Internal Network", "Email", "Web Application", "USB Device", "Cloud Service"]
    targets = ["Database Server", "Web Server", "User Workstation", "Domain Controller", "File Server"]
    statuses = ["Active", "Investigating", "Contained", "Resolved"]
    
    data = []
    for i in range(15):
        threat_type = np.random.choice(threat_types)
        severity = np.random.choice(severities, p=[0.1, 0.3, 0.4, 0.2])
        
        data.append({
            "Type": threat_type,
            "Severity": severity,
            "Source": np.random.choice(sources),
            "Target": np.random.choice(targets),
            "Risk_Score": np.random.randint(1, 11),
            "Detected": (datetime.now() - timedelta(hours=np.random.randint(0, 48))).strftime("%Y-%m-%d %H:%M"),
            "Status": np.random.choice(statuses),
            "Action": get_recommended_action(threat_type, severity),
            "Description": f"Detected {threat_type.lower()} activity with {severity.lower()} severity level"
        })
    
    return pd.DataFrame(data)

def generate_threat_timeline():
    """Generate timeline data for visualization"""
    times = pd.date_range(start=datetime.now() - timedelta(days=7), 
                         end=datetime.now(), freq='4H')
    
    data = []
    threat_types = ["Malware", "Phishing", "DDoS", "Intrusion"]
    severities = ["Critical", "High", "Medium", "Low"]
    severity_mapping = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    
    for time in times:
        if np.random.random() > 0.3:  # 70% chance of threat at each time point
            threat_type = np.random.choice(threat_types)
            severity = np.random.choice(severities, p=[0.1, 0.2, 0.4, 0.3])
            
            data.append({
                "Time": time,
                "Type": threat_type,
                "Severity": severity,
                "Severity_Numeric": severity_mapping[severity],
                "Risk_Score": np.random.randint(1, 11),
                "Source": np.random.choice(["External", "Internal", "Unknown"]),
                "Target": np.random.choice(["Server", "Workstation", "Network"])
            })
    
    return pd.DataFrame(data)

def get_recommended_action(threat_type, severity):
    """Get recommended action based on threat type and severity"""
    actions = {
        ("Malware", "Critical"): "Immediate isolation and removal",
        ("Phishing", "High"): "Block sender and educate users",
        ("DDoS", "High"): "Activate DDoS protection",
        ("SQL Injection", "Critical"): "Patch database and review logs",
        ("XSS", "Medium"): "Sanitize inputs and update WAF rules",
        ("Data Breach", "Critical"): "Incident response activation",
        ("Ransomware", "Critical"): "Immediate isolation and backup restore"
    }
    
    return actions.get((threat_type, severity), "Monitor and investigate")

def get_threat_intelligence():
    """Get current threat intelligence data"""
    return [
        {
            "source": "CERT Advisory",
            "description": "New ransomware variant targeting healthcare organizations detected"
        },
        {
            "source": "Threat Feed",
            "description": "Increased phishing activity using COVID-19 themes"
        },
        {
            "source": "Security Research",
            "description": "Zero-day vulnerability discovered in popular web framework"
        }
    ]
