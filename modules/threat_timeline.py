"""
Interactive Threat Timeline with Micro-interactions
Advanced timeline visualization for security events with smooth animations and intuitive interactions
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import numpy as np
from typing import Dict, List, Any, Optional
import time
import json

def show_threat_timeline():
    """Main threat timeline interface with micro-interactions"""
    st.header("📈 Interactive Threat Timeline")
    st.markdown("Visualize security events with intuitive interactions and real-time updates")
    
    # Timeline controls with smooth interactions
    col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
    
    with col1:
        time_range = st.selectbox(
            "⏰ Time Range",
            ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom"],
            index=1,
            help="Select the time period for threat analysis"
        )
    
    with col2:
        severity_filter = st.multiselect(
            "🎯 Severity Levels",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM"],
            help="Filter threats by severity level"
        )
    
    with col3:
        event_types = st.multiselect(
            "🔍 Event Types",
            ["Malware", "Intrusion", "Data Breach", "Authentication", "Network", "Anomaly"],
            default=["Malware", "Intrusion", "Data Breach"],
            help="Select types of security events to display"
        )
    
    with col4:
        auto_refresh = st.checkbox(
            "🔄 Auto Refresh",
            value=False,
            help="Automatically refresh timeline every 30 seconds"
        )
    
    # Custom time range selector with date picker
    if time_range == "Custom":
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start Date", value=datetime.now() - timedelta(days=7))
        with col2:
            end_date = st.date_input("End Date", value=datetime.now())
    
    # Generate timeline data based on filters
    timeline_data = generate_timeline_data(time_range, severity_filter, event_types)
    
    if not timeline_data.empty:
        # Main interactive timeline
        create_interactive_timeline(timeline_data, auto_refresh)
        
        # Timeline statistics with animated cards
        show_timeline_statistics(timeline_data)
        
        # Event details with expandable cards
        show_event_details(timeline_data)
        
        # Timeline insights with AI analysis
        show_timeline_insights(timeline_data)
    else:
        st.info("🔍 No threat events found for the selected criteria. Adjust your filters to view more data.")

def generate_timeline_data(time_range: str, severity_filter: List[str], event_types: List[str]) -> pd.DataFrame:
    """Generate realistic timeline data for the specified filters"""
    
    # Determine time bounds
    now = datetime.now()
    if time_range == "Last Hour":
        start_time = now - timedelta(hours=1)
    elif time_range == "Last 24 Hours":
        start_time = now - timedelta(days=1)
    elif time_range == "Last 7 Days":
        start_time = now - timedelta(days=7)
    elif time_range == "Last 30 Days":
        start_time = now - timedelta(days=30)
    else:
        start_time = now - timedelta(days=7)  # Default
    
    # Generate sample threat events
    events = []
    event_count = np.random.randint(15, 50)
    
    for i in range(event_count):
        event_time = start_time + timedelta(
            seconds=np.random.randint(0, int((now - start_time).total_seconds()))
        )
        
        severity = np.random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], 
                                  p=[0.1, 0.3, 0.4, 0.2])
        event_type = np.random.choice(event_types if event_types else ["Malware"])
        
        # Only include events matching filters
        if severity in severity_filter:
            events.append({
                'timestamp': event_time,
                'severity': severity,
                'event_type': event_type,
                'title': generate_event_title(event_type, severity),
                'description': generate_event_description(event_type),
                'source_ip': generate_ip(),
                'target_asset': generate_asset_name(),
                'confidence': np.random.randint(70, 100),
                'impact_score': np.random.randint(1, 10),
                'status': np.random.choice(['New', 'Investigating', 'Contained', 'Resolved'], 
                                         p=[0.4, 0.3, 0.2, 0.1]),
                'analyst': np.random.choice(['Sarah Chen', 'Mike Rodriguez', 'Alex Kim', 'Emma Davis']),
                'iocs': generate_iocs(),
                'remediation': generate_remediation_steps(event_type)
            })
    
    return pd.DataFrame(events).sort_values('timestamp')

def create_interactive_timeline(data: pd.DataFrame, auto_refresh: bool):
    """Create the main interactive timeline visualization"""
    
    # Prepare data for plotting
    data['hover_text'] = data.apply(lambda row: 
        f"<b>{row['title']}</b><br>" +
        f"Time: {row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}<br>" +
        f"Severity: {row['severity']}<br>" +
        f"Asset: {row['target_asset']}<br>" +
        f"Confidence: {row['confidence']}%<br>" +
        f"Status: {row['status']}", axis=1
    )
    
    # Color mapping for severity levels
    severity_colors = {
        'CRITICAL': '#FF0000',
        'HIGH': '#FF6600',
        'MEDIUM': '#FFAA00',
        'LOW': '#00AA00'
    }
    
    data['color'] = data['severity'].map(severity_colors)
    data['size'] = data['severity'].map({
        'CRITICAL': 20,
        'HIGH': 16,
        'MEDIUM': 12,
        'LOW': 8
    })
    
    # Create the timeline plot
    fig = go.Figure()
    
    # Add scatter points for each severity level
    for severity in data['severity'].unique():
        severity_data = data[data['severity'] == severity]
        
        fig.add_trace(go.Scatter(
            x=severity_data['timestamp'],
            y=severity_data['impact_score'],
            mode='markers+lines',
            name=severity,
            marker=dict(
                size=severity_data['size'],
                color=severity_colors[severity],
                opacity=0.8,
                line=dict(width=2, color='white'),
                symbol='circle'
            ),
            line=dict(
                width=2,
                color=severity_colors[severity],
                dash='dot'
            ),
            hovertemplate=severity_data['hover_text'] + '<extra></extra>',
            showlegend=True
        ))
    
    # Customize layout with smooth animations
    fig.update_layout(
        title=dict(
            text="🚨 Threat Event Timeline",
            font=dict(size=20, color='#2E86AB'),
            x=0.5
        ),
        xaxis=dict(
            title="Time",
            showgrid=True,
            gridcolor='rgba(128,128,128,0.2)',
            zeroline=False,
            tickformat='%H:%M\n%m/%d'
        ),
        yaxis=dict(
            title="Impact Score",
            showgrid=True,
            gridcolor='rgba(128,128,128,0.2)',
            zeroline=False,
            range=[0, 10]
        ),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        height=500,
        hovermode='closest',
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        margin=dict(l=50, r=50, t=80, b=50),
        transition=dict(
            duration=500,
            easing="cubic-in-out"
        )
    )
    
    # Add range selector for quick time navigation
    fig.update_layout(
        xaxis=dict(
            rangeselector=dict(
                buttons=list([
                    dict(count=1, label="1H", step="hour", stepmode="backward"),
                    dict(count=6, label="6H", step="hour", stepmode="backward"),
                    dict(count=1, label="1D", step="day", stepmode="backward"),
                    dict(count=7, label="7D", step="day", stepmode="backward"),
                    dict(step="all")
                ])
            ),
            rangeslider=dict(visible=True),
            type="date"
        )
    )
    
    # Display the interactive timeline
    timeline_container = st.container()
    with timeline_container:
        selected_points = st.plotly_chart(
            fig, 
            use_container_width=True,
            selection_mode="points"
        )
        
        # Auto-refresh functionality
        if auto_refresh:
            time.sleep(30)
            st.rerun()

def show_timeline_statistics(data: pd.DataFrame):
    """Display animated statistics cards"""
    st.subheader("📊 Timeline Statistics")
    
    # Calculate statistics
    total_events = len(data)
    critical_events = len(data[data['severity'] == 'CRITICAL'])
    avg_confidence = data['confidence'].mean()
    resolution_rate = len(data[data['status'] == 'Resolved']) / total_events * 100 if total_events > 0 else 0
    
    # Create animated metric cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="🎯 Total Events",
            value=total_events,
            delta=f"+{np.random.randint(1, 5)} from last period",
            help="Total number of threat events in the selected timeframe"
        )
    
    with col2:
        st.metric(
            label="🔥 Critical Events",
            value=critical_events,
            delta=f"+{np.random.randint(0, 3)} from last period" if critical_events > 0 else "No change",
            delta_color="inverse",
            help="Number of critical severity events requiring immediate attention"
        )
    
    with col3:
        st.metric(
            label="📈 Avg Confidence",
            value=f"{avg_confidence:.1f}%",
            delta=f"+{np.random.uniform(-2.5, 2.5):.1f}% from last period",
            help="Average confidence level of threat detections"
        )
    
    with col4:
        st.metric(
            label="✅ Resolution Rate",
            value=f"{resolution_rate:.1f}%",
            delta=f"+{np.random.uniform(-5, 10):.1f}% from last period",
            help="Percentage of events that have been resolved"
        )

def show_event_details(data: pd.DataFrame):
    """Display expandable event detail cards with micro-interactions"""
    st.subheader("🔍 Event Details")
    
    # Sort by severity and timestamp
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    data_sorted = data.sort_values(['timestamp'], ascending=False)
    
    # Show recent events with expandable cards
    st.markdown("**Recent Threat Events**")
    
    for idx, event in data_sorted.head(10).iterrows():
        severity_emoji = {
            'CRITICAL': '🔥',
            'HIGH': '🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        status_emoji = {
            'New': '🆕',
            'Investigating': '🔍',
            'Contained': '🛡️',
            'Resolved': '✅'
        }
        
        # Create expandable card for each event
        with st.expander(
            f"{severity_emoji[event['severity']]} {event['title']} - {event['timestamp'].strftime('%H:%M:%S')}",
            expanded=False
        ):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Description:** {event['description']}")
                st.markdown(f"**Target Asset:** {event['target_asset']}")
                st.markdown(f"**Source IP:** {event['source_ip']}")
                st.markdown(f"**Analyst:** {event['analyst']}")
                
                # IOCs with copy functionality
                if event['iocs']:
                    st.markdown("**Indicators of Compromise:**")
                    for ioc in event['iocs']:
                        st.code(ioc, language=None)
            
            with col2:
                # Status badge
                st.markdown(f"**Status:** {status_emoji[event['status']]} {event['status']}")
                st.markdown(f"**Confidence:** {event['confidence']}%")
                st.markdown(f"**Impact Score:** {event['impact_score']}/10")
                
                # Action buttons
                if event['status'] != 'Resolved':
                    if st.button(f"🔄 Update Status", key=f"status_{idx}"):
                        st.success("Status updated successfully!")
                
                if st.button(f"📋 View Details", key=f"details_{idx}"):
                    show_detailed_event_analysis(event)

def show_detailed_event_analysis(event: Dict[str, Any]):
    """Show detailed analysis for a specific event"""
    st.subheader(f"🔬 Detailed Analysis: {event['title']}")
    
    # Create tabs for different analysis views
    tab1, tab2, tab3, tab4 = st.tabs(["📋 Overview", "🔍 Investigation", "🛡️ Response", "📊 Context"])
    
    with tab1:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Event Information**")
            st.markdown(f"- **Time:** {event['timestamp']}")
            st.markdown(f"- **Severity:** {event['severity']}")
            st.markdown(f"- **Type:** {event['event_type']}")
            st.markdown(f"- **Confidence:** {event['confidence']}%")
        
        with col2:
            st.markdown("**Asset Information**")
            st.markdown(f"- **Target:** {event['target_asset']}")
            st.markdown(f"- **Source IP:** {event['source_ip']}")
            st.markdown(f"- **Impact Score:** {event['impact_score']}/10")
    
    with tab2:
        st.markdown("**Investigation Timeline**")
        investigation_steps = [
            {"time": "00:30", "action": "Alert triggered", "status": "completed"},
            {"time": "00:45", "action": "Initial analysis", "status": "completed"},
            {"time": "01:00", "action": "Asset isolation", "status": "in_progress"},
            {"time": "01:15", "action": "Forensic collection", "status": "pending"}
        ]
        
        for step in investigation_steps:
            status_color = {"completed": "green", "in_progress": "orange", "pending": "gray"}[step['status']]
            st.markdown(f"🕐 **{step['time']}** - {step['action']} :{status_color}[●]")
    
    with tab3:
        st.markdown("**Recommended Response Actions**")
        for action in event['remediation']:
            st.markdown(f"- {action}")
        
        st.markdown("**Response Playbook**")
        st.info(f"Following standard {event['event_type']} response procedures")
    
    with tab4:
        st.markdown("**Threat Context**")
        st.markdown("Related events in the last 24 hours:")
        # Show related events context
        st.bar_chart(pd.DataFrame({
            'Hour': range(24),
            'Similar Events': np.random.poisson(2, 24)
        }).set_index('Hour'))

def show_timeline_insights(data: pd.DataFrame):
    """Display AI-powered insights from timeline analysis"""
    st.subheader("🧠 Timeline Insights")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**🔍 Pattern Analysis**")
        
        # Time-based patterns
        hourly_counts = data.groupby(data['timestamp'].dt.hour).size()
        peak_hour = hourly_counts.idxmax() if not hourly_counts.empty else 0
        
        insights = [
            f"Peak activity detected at {peak_hour:02d}:00 hours",
            f"Most common attack vector: {data['event_type'].mode().iloc[0] if not data.empty else 'N/A'}",
            f"Average time between events: {calculate_avg_time_between_events(data)} minutes",
            f"Threat escalation trend: {'Increasing' if np.random.random() > 0.5 else 'Stable'}"
        ]
        
        for insight in insights:
            st.markdown(f"• {insight}")
    
    with col2:
        st.markdown("**📈 Trend Analysis**")
        
        # Create mini trend chart
        if not data.empty:
            hourly_data = data.groupby(data['timestamp'].dt.floor('H')).size().reset_index()
            hourly_data.columns = ['hour', 'count']
            
            fig = px.line(
                hourly_data, 
                x='hour', 
                y='count',
                title="Threat Activity Trend"
            )
            fig.update_layout(height=300, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        # AI recommendations
        st.markdown("**🤖 AI Recommendations**")
        recommendations = [
            "Consider increasing monitoring during peak hours",
            "Review security policies for detected attack vectors",
            "Investigate correlation between network anomalies and auth failures",
            "Schedule additional SOC staffing for high-activity periods"
        ]
        
        for rec in recommendations:
            st.markdown(f"💡 {rec}")

def generate_event_title(event_type: str, severity: str) -> str:
    """Generate realistic event titles"""
    titles = {
        'Malware': [
            'Trojan.Generic detected on endpoint',
            'Ransomware activity blocked',
            'Suspicious executable quarantined',
            'Malicious PowerShell script detected'
        ],
        'Intrusion': [
            'Unauthorized access attempt detected',
            'Lateral movement activity observed',
            'Privilege escalation attempt',
            'Suspicious network scanning detected'
        ],
        'Data Breach': [
            'Unauthorized data access detected',
            'Large data transfer to external IP',
            'Sensitive file access anomaly',
            'Database exfiltration attempt'
        ],
        'Authentication': [
            'Multiple failed login attempts',
            'Brute force attack detected',
            'Suspicious login from new location',
            'Account lockout threshold exceeded'
        ],
        'Network': [
            'DDoS attack detected',
            'Suspicious network traffic pattern',
            'Port scanning activity',
            'Bandwidth anomaly detected'
        ],
        'Anomaly': [
            'User behavior anomaly detected',
            'System performance anomaly',
            'Network traffic anomaly',
            'Application usage anomaly'
        ]
    }
    
    return np.random.choice(titles.get(event_type, ['Unknown security event']))

def generate_event_description(event_type: str) -> str:
    """Generate realistic event descriptions"""
    descriptions = {
        'Malware': 'Malicious software detected attempting to compromise system integrity',
        'Intrusion': 'Unauthorized access attempt from external or internal source',
        'Data Breach': 'Potential unauthorized access or exfiltration of sensitive data',
        'Authentication': 'Authentication-related security event requiring investigation',
        'Network': 'Network-based security event affecting infrastructure',
        'Anomaly': 'Unusual system or user behavior detected by AI algorithms'
    }
    
    return descriptions.get(event_type, 'Security event requiring investigation')

def generate_ip() -> str:
    """Generate realistic IP addresses"""
    return f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"

def generate_asset_name() -> str:
    """Generate realistic asset names"""
    prefixes = ['SRV', 'WS', 'DB', 'WEB', 'APP', 'DC']
    numbers = ['001', '002', '003', '004', '005']
    return f"{np.random.choice(prefixes)}-{np.random.choice(numbers)}"

def generate_iocs() -> List[str]:
    """Generate realistic IOCs"""
    iocs = [
        f"MD5: {np.random.choice(['a1b2c3d4e5', 'f6g7h8i9j0', 'k1l2m3n4o5'])}",
        f"IP: {generate_ip()}",
        f"Domain: malicious-{np.random.randint(100, 999)}.com",
        f"Registry: HKLM\\Software\\{np.random.choice(['Malware', 'Backdoor', 'Trojan'])}"
    ]
    return np.random.choice(iocs, size=np.random.randint(1, 3), replace=False).tolist()

def generate_remediation_steps(event_type: str) -> List[str]:
    """Generate realistic remediation steps"""
    steps = {
        'Malware': [
            'Isolate affected endpoint from network',
            'Run full system antivirus scan',
            'Check for persistence mechanisms',
            'Update endpoint protection signatures'
        ],
        'Intrusion': [
            'Block source IP address',
            'Review access logs',
            'Check for lateral movement',
            'Reset compromised credentials'
        ],
        'Data Breach': [
            'Identify scope of data exposure',
            'Secure affected data sources',
            'Notify relevant stakeholders',
            'Implement additional monitoring'
        ]
    }
    
    return steps.get(event_type, ['Investigate and contain threat', 'Document findings', 'Implement preventive measures'])

def calculate_avg_time_between_events(data: pd.DataFrame) -> int:
    """Calculate average time between events in minutes"""
    if len(data) < 2:
        return 0
    
    time_diffs = data['timestamp'].diff().dropna()
    avg_diff = time_diffs.mean()
    return int(avg_diff.total_seconds() / 60) if pd.notna(avg_diff) else 0