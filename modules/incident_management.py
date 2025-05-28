import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

def show_incident_management():
    """Security incident management and response"""
    st.header("🚨 Security Incident Management & Response")
    
    # Incident metrics overview
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Open Incidents", "12", delta="+3")
    with col2:
        st.metric("Critical Incidents", "2", delta="+1")
    with col3:
        st.metric("Avg Response Time", "18 min", delta="-5 min")
    with col4:
        st.metric("Resolution Rate", "94%", delta="+2%")
    
    st.divider()
    
    # Incident creation
    st.subheader("📝 Create New Incident")
    
    col1, col2 = st.columns(2)
    
    with col1:
        incident_title = st.text_input("Incident Title")
        incident_type = st.selectbox(
            "Incident Type",
            ["Malware Detection", "Data Breach", "Unauthorized Access", "DDoS Attack", 
             "Phishing Campaign", "System Compromise", "Policy Violation", "Other"]
        )
        severity = st.selectbox("Severity", ["Critical", "High", "Medium", "Low"])
    
    with col2:
        affected_systems = st.multiselect(
            "Affected Systems",
            ["Web Server", "Database", "Email Server", "File Server", "Domain Controller", 
             "Workstations", "Network Infrastructure", "Cloud Services"]
        )
        assigned_to = st.selectbox(
            "Assign To",
            ["SOC Team", "Network Admin", "Security Analyst", "Incident Commander", "External Consultant"]
        )
        
        if st.button("Create Incident"):
            if incident_title and incident_type:
                create_incident(incident_title, incident_type, severity, affected_systems, assigned_to)
            else:
                st.error("Please fill in required fields")
    
    # Active incidents dashboard
    st.subheader("🎯 Active Incidents")
    
    # Incident filtering
    col1, col2, col3 = st.columns(3)
    
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["All", "New", "In Progress", "Under Investigation", "Resolved", "Closed"]
        )
    
    with col2:
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All", "Critical", "High", "Medium", "Low"]
        )
    
    with col3:
        assignee_filter = st.selectbox(
            "Filter by Assignee",
            ["All", "SOC Team", "Network Admin", "Security Analyst", "Incident Commander"]
        )
    
    # Generate and display incidents
    incidents = generate_incident_data()
    filtered_incidents = apply_incident_filters(incidents, status_filter, severity_filter, assignee_filter)
    
    for _, incident in filtered_incidents.iterrows():
        severity_color = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }.get(incident['Severity'], "🔵")
        
        status_color = {
            "New": "🆕",
            "In Progress": "🔄",
            "Under Investigation": "🔍",
            "Resolved": "✅",
            "Closed": "📁"
        }.get(incident['Status'], "📋")
        
        with st.expander(f"{severity_color} {status_color} INC-{incident.name:04d}: {incident['Title']}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Type:** {incident['Type']}")
                st.write(f"**Severity:** {incident['Severity']}")
                st.write(f"**Status:** {incident['Status']}")
                st.write(f"**Created:** {incident['Created']}")
                st.write(f"**Last Updated:** {incident['Last_Updated']}")
            
            with col2:
                st.write(f"**Assigned To:** {incident['Assigned_To']}")
                st.write(f"**Affected Systems:** {incident['Affected_Systems']}")
                st.write(f"**Response Time:** {incident['Response_Time']}")
                st.write(f"**Resolution ETA:** {incident['Resolution_ETA']}")
                st.write(f"**Priority Score:** {incident['Priority_Score']}/10")
            
            st.write(f"**Description:** {incident['Description']}")
            
            # Incident timeline
            if st.button(f"View Timeline", key=f"timeline_{incident.name}"):
                show_incident_timeline(incident.name)
            
            # Action buttons
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                if st.button(f"Update Status", key=f"update_{incident.name}"):
                    update_incident_status(incident)
            
            with col2:
                if st.button(f"Escalate", key=f"escalate_{incident.name}"):
                    escalate_incident(incident)
            
            with col3:
                if st.button(f"Add Notes", key=f"notes_{incident.name}"):
                    add_incident_notes(incident)
            
            with col4:
                if st.button(f"Generate Report", key=f"report_{incident.name}"):
                    generate_incident_report(incident)
    
    # Incident analytics and trends
    st.subheader("📊 Incident Analytics & Trends")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Incident trends over time
        trend_data = generate_incident_trends()
        fig = px.line(trend_data, x='Date', y='Incident_Count', 
                     color='Severity', title="Incident Trends Over Time")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Incident distribution by type
        type_distribution = incidents['Type'].value_counts()
        fig = px.bar(x=type_distribution.index, y=type_distribution.values,
                     title="Incidents by Type")
        st.plotly_chart(fig, use_container_width=True)
    
    # Response performance metrics
    st.subheader("⏱️ Response Performance Metrics")
    
    performance_data = calculate_performance_metrics(incidents)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Average Response Time", performance_data['avg_response'], delta=performance_data['response_delta'])
        st.metric("Average Resolution Time", performance_data['avg_resolution'], delta=performance_data['resolution_delta'])
    
    with col2:
        st.metric("SLA Compliance", f"{performance_data['sla_compliance']}%", delta=f"+{performance_data['sla_delta']}%")
        st.metric("First Call Resolution", f"{performance_data['fcr_rate']}%", delta=f"+{performance_data['fcr_delta']}%")
    
    with col3:
        # Response time distribution
        response_times = [15, 22, 8, 45, 12, 30, 18, 25, 10, 35, 20, 28]
        fig = px.histogram(x=response_times, nbins=10, title="Response Time Distribution")
        fig.update_xaxis(title="Response Time (minutes)")
        fig.update_yaxis(title="Frequency")
        st.plotly_chart(fig, use_container_width=True)
    
    # Incident playbooks and automation
    st.subheader("📚 Incident Playbooks & Automation")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Available Playbooks:**")
        playbooks = get_incident_playbooks()
        for playbook in playbooks:
            if st.button(playbook['name'], key=f"playbook_{playbook['id']}"):
                st.info(f"Executing {playbook['name']} playbook...")
                st.write(f"Steps: {playbook['steps']}")
    
    with col2:
        st.write("**Automated Responses:**")
        automated_responses = get_automated_responses()
        for response in automated_responses:
            status_icon = "✅" if response['enabled'] else "❌"
            st.write(f"{status_icon} {response['name']}: {response['description']}")
    
    # Incident reporting and documentation
    st.subheader("📄 Incident Reporting & Documentation")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Generate Daily Report"):
            st.success("Daily incident report generated and sent to stakeholders")
    
    with col2:
        if st.button("Export Incident Data"):
            st.success("Incident data exported to CSV format")
    
    with col3:
        if st.button("Create Post-Incident Review"):
            st.info("Post-incident review template created for critical incidents")

def create_incident(title, inc_type, severity, systems, assignee):
    """Create a new security incident"""
    incident_id = f"INC-{np.random.randint(1000, 9999)}"
    
    st.success(f"Incident {incident_id} created successfully!")
    st.info(f"**Title:** {title}\n**Type:** {inc_type}\n**Severity:** {severity}\n**Assigned to:** {assignee}")
    
    # Trigger automated response if critical
    if severity == "Critical":
        st.warning("🚨 Critical incident detected! Automated response protocols initiated.")

def generate_incident_data():
    """Generate realistic incident data"""
    incident_types = ["Malware Detection", "Data Breach", "Unauthorized Access", "DDoS Attack", 
                     "Phishing Campaign", "System Compromise", "Policy Violation"]
    severities = ["Critical", "High", "Medium", "Low"]
    statuses = ["New", "In Progress", "Under Investigation", "Resolved", "Closed"]
    assignees = ["SOC Team", "Network Admin", "Security Analyst", "Incident Commander"]
    systems = ["Web Server", "Database", "Email Server", "File Server", "Workstations"]
    
    data = []
    for i in range(15):
        severity = np.random.choice(severities, p=[0.1, 0.3, 0.4, 0.2])
        status = np.random.choice(statuses, p=[0.2, 0.3, 0.2, 0.2, 0.1])
        
        created_time = datetime.now() - timedelta(hours=np.random.randint(1, 168))  # Last week
        
        data.append({
            'Title': f"{np.random.choice(incident_types)} - {np.random.choice(['Server', 'Network', 'User', 'Application'])} {i+1}",
            'Type': np.random.choice(incident_types),
            'Severity': severity,
            'Status': status,
            'Assigned_To': np.random.choice(assignees),
            'Affected_Systems': ', '.join(np.random.choice(systems, size=np.random.randint(1, 4), replace=False)),
            'Created': created_time.strftime("%Y-%m-%d %H:%M"),
            'Last_Updated': (created_time + timedelta(hours=np.random.randint(1, 24))).strftime("%Y-%m-%d %H:%M"),
            'Response_Time': f"{np.random.randint(5, 60)} minutes",
            'Resolution_ETA': f"{np.random.randint(1, 72)} hours",
            'Priority_Score': np.random.randint(1, 11),
            'Description': f"Security incident involving {np.random.choice(incident_types).lower()} detected through automated monitoring systems."
        })
    
    return pd.DataFrame(data)

def apply_incident_filters(data, status_filter, severity_filter, assignee_filter):
    """Apply filters to incident data"""
    filtered_data = data.copy()
    
    if status_filter != "All":
        filtered_data = filtered_data[filtered_data['Status'] == status_filter]
    
    if severity_filter != "All":
        filtered_data = filtered_data[filtered_data['Severity'] == severity_filter]
    
    if assignee_filter != "All":
        filtered_data = filtered_data[filtered_data['Assigned_To'] == assignee_filter]
    
    return filtered_data

def show_incident_timeline(incident_id):
    """Show incident timeline"""
    st.subheader(f"📅 Timeline for INC-{incident_id:04d}")
    
    timeline_events = [
        {'time': '2024-01-15 09:15', 'event': 'Incident detected by automated monitoring', 'user': 'System'},
        {'time': '2024-01-15 09:18', 'event': 'Incident created and assigned to SOC Team', 'user': 'Auto-Assignment'},
        {'time': '2024-01-15 09:25', 'event': 'Initial investigation started', 'user': 'analyst1'},
        {'time': '2024-01-15 09:45', 'event': 'Affected systems identified and isolated', 'user': 'analyst1'},
        {'time': '2024-01-15 10:30', 'event': 'Escalated to Security Manager', 'user': 'analyst1'},
        {'time': '2024-01-15 11:15', 'event': 'Containment measures implemented', 'user': 'sec_manager'},
        {'time': '2024-01-15 14:20', 'event': 'Root cause analysis completed', 'user': 'analyst2'},
        {'time': '2024-01-15 15:45', 'event': 'Resolution steps initiated', 'user': 'sec_manager'}
    ]
    
    for event in timeline_events:
        st.write(f"**{event['time']}** - {event['event']} *(by {event['user']})*")

def update_incident_status(incident):
    """Update incident status"""
    new_status = st.selectbox(
        "Select new status:",
        ["New", "In Progress", "Under Investigation", "Resolved", "Closed"],
        key=f"status_update_{incident.name}"
    )
    
    if st.button("Update", key=f"confirm_update_{incident.name}"):
        st.success(f"Incident status updated to: {new_status}")

def escalate_incident(incident):
    """Escalate incident"""
    escalation_options = ["Security Manager", "CISO", "Incident Commander", "External Consultant"]
    escalate_to = st.selectbox(
        "Escalate to:",
        escalation_options,
        key=f"escalate_to_{incident.name}"
    )
    
    if st.button("Escalate", key=f"confirm_escalate_{incident.name}"):
        st.warning(f"Incident escalated to: {escalate_to}")

def add_incident_notes(incident):
    """Add notes to incident"""
    notes = st.text_area(
        "Add investigation notes:",
        key=f"notes_{incident.name}"
    )
    
    if st.button("Add Notes", key=f"confirm_notes_{incident.name}"):
        if notes:
            st.success("Notes added to incident record")

def generate_incident_report(incident):
    """Generate incident report"""
    report_type = st.selectbox(
        "Report Type:",
        ["Summary Report", "Detailed Investigation", "Executive Brief", "Technical Analysis"],
        key=f"report_type_{incident.name}"
    )
    
    if st.button("Generate", key=f"confirm_report_{incident.name}"):
        st.success(f"{report_type} generated for incident INC-{incident.name:04d}")

def generate_incident_trends():
    """Generate incident trend data"""
    dates = pd.date_range(start=datetime.now() - timedelta(days=30), 
                         end=datetime.now(), freq='D')
    
    severities = ['Critical', 'High', 'Medium', 'Low']
    data = []
    
    for date in dates:
        for severity in severities:
            # Simulate realistic incident patterns
            base_count = {'Critical': 0.5, 'High': 2, 'Medium': 4, 'Low': 3}[severity]
            count = max(0, int(base_count + np.random.normal(0, 1)))
            
            data.append({
                'Date': date,
                'Severity': severity,
                'Incident_Count': count
            })
    
    return pd.DataFrame(data)

def calculate_performance_metrics(incidents):
    """Calculate incident response performance metrics"""
    return {
        'avg_response': "18 min",
        'response_delta': "-5 min",
        'avg_resolution': "4.2 hours",
        'resolution_delta': "-1.3 hours",
        'sla_compliance': 94,
        'sla_delta': 2,
        'fcr_rate': 78,
        'fcr_delta': 5
    }

def get_incident_playbooks():
    """Get available incident response playbooks"""
    return [
        {
            'id': 1,
            'name': 'Malware Response',
            'steps': 'Isolate → Analyze → Contain → Eradicate → Recover'
        },
        {
            'id': 2,
            'name': 'Data Breach Response',
            'steps': 'Assess → Contain → Investigate → Notify → Remediate'
        },
        {
            'id': 3,
            'name': 'DDoS Mitigation',
            'steps': 'Detect → Activate Protection → Monitor → Analyze → Report'
        },
        {
            'id': 4,
            'name': 'Phishing Campaign',
            'steps': 'Block → Alert Users → Investigate → Remove → Educate'
        }
    ]

def get_automated_responses():
    """Get automated response configurations"""
    return [
        {
            'name': 'Auto-isolation',
            'description': 'Automatically isolate infected systems',
            'enabled': True
        },
        {
            'name': 'User Notification',
            'description': 'Send alerts to affected users',
            'enabled': True
        },
        {
            'name': 'IP Blocking',
            'description': 'Block malicious IP addresses',
            'enabled': True
        },
        {
            'name': 'System Shutdown',
            'description': 'Emergency system shutdown for critical threats',
            'enabled': False
        }
    ]
