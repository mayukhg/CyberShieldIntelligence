import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

def show_network_analysis():
    """Network traffic analysis and monitoring"""
    st.header("🌐 Network Traffic Analysis & Monitoring")
    
    # Network metrics overview
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Traffic", "4.2 GB/hr", delta="+8%")
    with col2:
        st.metric("Suspicious Connections", "34", delta="+12")
    with col3:
        st.metric("Blocked IPs", "156", delta="+23")
    with col4:
        st.metric("Bandwidth Utilization", "67%", delta="+5%")
    
    st.divider()
    
    # Network monitoring controls
    st.subheader("🎛️ Monitoring Controls")
    
    col1, col2 = st.columns(2)
    
    with col1:
        monitoring_mode = st.selectbox(
            "Monitoring Mode",
            ["Real-time", "Batch Analysis", "Deep Packet Inspection"]
        )
        
        analysis_depth = st.slider(
            "Analysis Depth",
            min_value=1, max_value=5, value=3,
            help="1=Basic, 5=Deep Analysis"
        )
    
    with col2:
        protocols = st.multiselect(
            "Monitor Protocols",
            ["HTTP", "HTTPS", "FTP", "SSH", "DNS", "SMTP", "All"],
            default=["HTTP", "HTTPS", "DNS"]
        )
        
        if st.button("Start Network Scan"):
            perform_network_scan(protocols, analysis_depth)
    
    # Real-time traffic visualization
    st.subheader("📊 Real-time Traffic Analysis")
    
    # Generate network traffic data
    traffic_data = generate_traffic_data()
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Traffic over time
        fig = create_traffic_timeline(traffic_data)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Protocol distribution
        protocol_data = traffic_data.groupby('Protocol')['Bytes'].sum()
        fig = px.pie(values=protocol_data.values, names=protocol_data.index,
                     title="Traffic by Protocol")
        st.plotly_chart(fig, use_container_width=True)
    
    # Suspicious connections
    st.subheader("🚨 Suspicious Network Activity")
    
    suspicious_connections = generate_suspicious_connections()
    
    # Connection filtering
    col1, col2, col3 = st.columns(3)
    
    with col1:
        risk_filter = st.selectbox(
            "Risk Level",
            ["All", "Critical", "High", "Medium", "Low"]
        )
    
    with col2:
        protocol_filter = st.selectbox(
            "Protocol Filter",
            ["All"] + list(suspicious_connections['Protocol'].unique())
        )
    
    with col3:
        time_filter = st.selectbox(
            "Time Range",
            ["Last Hour", "Last 6 Hours", "Last 24 Hours", "Last Week"]
        )
    
    # Apply filters
    filtered_connections = apply_connection_filters(
        suspicious_connections, risk_filter, protocol_filter, time_filter
    )
    
    # Display suspicious connections
    for _, conn in filtered_connections.iterrows():
        risk_color = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }.get(conn['Risk_Level'], "🔵")
        
        with st.expander(f"{risk_color} {conn['Source_IP']} → {conn['Dest_IP']} ({conn['Protocol']})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Risk Level:** {conn['Risk_Level']}")
                st.write(f"**Protocol:** {conn['Protocol']}")
                st.write(f"**Port:** {conn['Port']}")
                st.write(f"**Connection Count:** {conn['Connection_Count']}")
            
            with col2:
                st.write(f"**Data Transferred:** {conn['Data_Transferred']}")
                st.write(f"**Duration:** {conn['Duration']}")
                st.write(f"**Location:** {conn['Geolocation']}")
                st.write(f"**First Seen:** {conn['First_Seen']}")
            
            st.write(f"**Threat Indicators:** {conn['Threat_Indicators']}")
            
            # Action buttons
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button(f"Block IP", key=f"block_{conn.name}"):
                    st.success(f"IP {conn['Source_IP']} has been blocked!")
            
            with col2:
                if st.button(f"Investigate", key=f"investigate_{conn.name}"):
                    show_connection_investigation(conn)
            
            with col3:
                if st.button(f"Whitelist", key=f"whitelist_{conn.name}"):
                    st.info(f"IP {conn['Source_IP']} added to whitelist")
    
    # Network topology and flow analysis
    st.subheader("🗺️ Network Topology & Flow Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Top talkers
        top_talkers = get_top_talkers()
        st.write("**Top Network Talkers:**")
        for talker in top_talkers:
            st.write(f"• {talker['ip']} - {talker['traffic']} ({talker['connections']} connections)")
    
    with col2:
        # Geographic traffic distribution
        geo_data = generate_geo_traffic_data()
        fig = px.scatter_mapbox(
            geo_data, lat='lat', lon='lon', size='traffic',
            color='risk_level', hover_name='country',
            mapbox_style='open-street-map',
            title="Global Traffic Distribution"
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # Bandwidth and performance metrics
    st.subheader("📈 Bandwidth & Performance Metrics")
    
    performance_data = generate_performance_data()
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Bandwidth utilization over time
        fig = px.line(performance_data, x='Time', y='Bandwidth_Utilization',
                     title="Bandwidth Utilization Over Time")
        fig.add_hline(y=80, line_dash="dash", line_color="red", 
                     annotation_text="Warning Threshold")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Latency metrics
        fig = px.box(performance_data, y='Latency',
                     title="Network Latency Distribution")
        st.plotly_chart(fig, use_container_width=True)
    
    # Network security rules and policies
    st.subheader("🛡️ Security Rules & Policies")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Active Firewall Rules:**")
        firewall_rules = get_firewall_rules()
        for rule in firewall_rules:
            st.write(f"• {rule['name']}: {rule['action']} {rule['traffic']}")
    
    with col2:
        st.write("**DDoS Protection Status:**")
        ddos_status = get_ddos_status()
        for status in ddos_status:
            status_icon = "🟢" if status['status'] == "Active" else "🔴"
            st.write(f"{status_icon} {status['protection']}: {status['status']}")

def perform_network_scan(protocols, depth):
    """Perform network security scan"""
    with st.spinner(f"Scanning network with depth level {depth}..."):
        progress = st.progress(0)
        for i in range(100):
            progress.progress(i + 1)
        
        st.success(f"Network scan completed! Found 12 potential issues across {len(protocols)} protocols.")

def generate_traffic_data():
    """Generate realistic network traffic data"""
    times = pd.date_range(start=datetime.now() - timedelta(hours=24), 
                         end=datetime.now(), freq='H')
    
    protocols = ['HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH', 'SMTP']
    data = []
    
    for time in times:
        for protocol in protocols:
            # Simulate realistic traffic patterns
            base_traffic = {
                'HTTP': 200000,
                'HTTPS': 800000,
                'DNS': 50000,
                'FTP': 100000,
                'SSH': 30000,
                'SMTP': 80000
            }
            
            # Add time-based variations (business hours effect)
            hour = time.hour
            multiplier = 1.5 if 9 <= hour <= 17 else 0.7
            
            bytes_transferred = int(base_traffic[protocol] * multiplier * np.random.uniform(0.5, 1.5))
            
            data.append({
                'Time': time,
                'Protocol': protocol,
                'Bytes': bytes_transferred,
                'Packets': bytes_transferred // 1000,
                'Connections': np.random.randint(10, 100)
            })
    
    return pd.DataFrame(data)

def create_traffic_timeline(data):
    """Create traffic timeline visualization"""
    fig = px.line(data, x='Time', y='Bytes', color='Protocol',
                  title="Network Traffic Over Time")
    
    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Bytes Transferred"
    )
    
    return fig

def generate_suspicious_connections():
    """Generate suspicious network connections data"""
    data = []
    risk_levels = ['Critical', 'High', 'Medium', 'Low']
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'SSH']
    threat_indicators = [
        'Multiple failed authentication attempts',
        'Unusual data exfiltration pattern',
        'Connection to known malicious IP',
        'Port scanning activity',
        'Suspicious payload detected',
        'Abnormal connection frequency',
        'Encrypted traffic to suspicious domain'
    ]
    
    for i in range(15):
        risk = np.random.choice(risk_levels, p=[0.1, 0.3, 0.4, 0.2])
        
        data.append({
            'Source_IP': f"{np.random.randint(1, 256)}.{np.random.randint(1, 256)}.{np.random.randint(1, 256)}.{np.random.randint(1, 256)}",
            'Dest_IP': f"192.168.1.{np.random.randint(1, 256)}",
            'Protocol': np.random.choice(protocols),
            'Port': np.random.choice([22, 80, 443, 21, 25, 53, 3389]),
            'Risk_Level': risk,
            'Connection_Count': np.random.randint(1, 1000),
            'Data_Transferred': f"{np.random.randint(1, 1000)} MB",
            'Duration': f"{np.random.randint(1, 300)} minutes",
            'Geolocation': np.random.choice(['Russia', 'China', 'US', 'Germany', 'Unknown']),
            'First_Seen': (datetime.now() - timedelta(hours=np.random.randint(0, 48))).strftime("%Y-%m-%d %H:%M"),
            'Threat_Indicators': np.random.choice(threat_indicators)
        })
    
    return pd.DataFrame(data)

def apply_connection_filters(data, risk_filter, protocol_filter, time_filter):
    """Apply filters to connection data"""
    filtered_data = data.copy()
    
    if risk_filter != "All":
        filtered_data = filtered_data[filtered_data['Risk_Level'] == risk_filter]
    
    if protocol_filter != "All":
        filtered_data = filtered_data[filtered_data['Protocol'] == protocol_filter]
    
    # Time filtering would be implemented here based on actual timestamps
    
    return filtered_data

def show_connection_investigation(conn):
    """Show detailed connection investigation"""
    st.info(f"**Investigation Report for {conn['Source_IP']}**")
    
    investigation_details = {
        "WHOIS Information": f"ISP: {np.random.choice(['Suspicious Cloud Provider', 'Known Hosting Service', 'Residential ISP'])}",
        "Reputation Score": f"{np.random.randint(1, 10)}/10 (Lower is more suspicious)",
        "Previous Incidents": f"{np.random.randint(0, 5)} similar connections in past 30 days",
        "Traffic Pattern": "Matches known botnet communication pattern",
        "Recommended Action": "Block IP and monitor for additional connections"
    }
    
    for key, value in investigation_details.items():
        st.write(f"**{key}:** {value}")

def get_top_talkers():
    """Get top network talkers"""
    return [
        {'ip': '192.168.1.100', 'traffic': '2.3 GB', 'connections': 1247},
        {'ip': '10.0.0.50', 'traffic': '1.8 GB', 'connections': 892},
        {'ip': '172.16.0.25', 'traffic': '1.2 GB', 'connections': 634},
        {'ip': '192.168.1.75', 'traffic': '950 MB', 'connections': 423},
        {'ip': '10.0.0.100', 'traffic': '780 MB', 'connections': 321}
    ]

def generate_geo_traffic_data():
    """Generate geographic traffic distribution data"""
    countries = [
        {'country': 'United States', 'lat': 39.8283, 'lon': -98.5795, 'traffic': 1000, 'risk_level': 'Low'},
        {'country': 'China', 'lat': 35.8617, 'lon': 104.1954, 'traffic': 800, 'risk_level': 'High'},
        {'country': 'Russia', 'lat': 61.5240, 'lon': 105.3188, 'traffic': 600, 'risk_level': 'High'},
        {'country': 'Germany', 'lat': 51.1657, 'lon': 10.4515, 'traffic': 400, 'risk_level': 'Low'},
        {'country': 'UK', 'lat': 55.3781, 'lon': -3.4360, 'traffic': 350, 'risk_level': 'Low'}
    ]
    
    return pd.DataFrame(countries)

def generate_performance_data():
    """Generate network performance metrics"""
    times = pd.date_range(start=datetime.now() - timedelta(hours=24), 
                         end=datetime.now(), freq='H')
    
    data = []
    for time in times:
        # Simulate realistic performance patterns
        hour = time.hour
        base_utilization = 50 + 30 * np.sin(2 * np.pi * hour / 24)  # Daily pattern
        utilization = max(0, min(100, base_utilization + np.random.normal(0, 10)))
        
        data.append({
            'Time': time,
            'Bandwidth_Utilization': utilization,
            'Latency': np.random.exponential(20),  # Exponential distribution for latency
            'Packet_Loss': np.random.exponential(0.1),
            'Jitter': np.random.exponential(5)
        })
    
    return pd.DataFrame(data)

def get_firewall_rules():
    """Get active firewall rules"""
    return [
        {'name': 'Block Malicious IPs', 'action': 'DENY', 'traffic': 'from known bad IP ranges'},
        {'name': 'Allow Internal HTTP', 'action': 'ALLOW', 'traffic': 'HTTP/HTTPS from internal network'},
        {'name': 'Block P2P', 'action': 'DENY', 'traffic': 'peer-to-peer protocols'},
        {'name': 'Allow SSH Admin', 'action': 'ALLOW', 'traffic': 'SSH from admin subnet'},
        {'name': 'Block High-Risk Ports', 'action': 'DENY', 'traffic': 'connections to high-risk ports'}
    ]

def get_ddos_status():
    """Get DDoS protection status"""
    return [
        {'protection': 'Rate Limiting', 'status': 'Active'},
        {'protection': 'GeoIP Blocking', 'status': 'Active'},
        {'protection': 'Behavioral Analysis', 'status': 'Active'},
        {'protection': 'Emergency Mode', 'status': 'Standby'},
        {'protection': 'Cloud Scrubbing', 'status': 'Active'}
    ]
