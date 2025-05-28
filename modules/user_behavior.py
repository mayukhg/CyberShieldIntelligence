import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

def show_user_behavior():
    """User behavior analytics for insider threat detection"""
    st.header("👤 User Behavior Analytics & Insider Threat Detection")
    
    # User behavior metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Users Monitored", "247", delta="+12")
    with col2:
        st.metric("Behavioral Anomalies", "18", delta="+3")
    with col3:
        st.metric("High-Risk Users", "5", delta="+2")
    with col4:
        st.metric("Policy Violations", "12", delta="-4")
    
    st.divider()
    
    # User behavior analysis controls
    st.subheader("⚙️ Analysis Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        analysis_period = st.selectbox(
            "Analysis Period",
            ["Real-time", "Last 24 Hours", "Last Week", "Last Month"]
        )
        
        risk_threshold = st.slider(
            "Risk Threshold",
            min_value=1, max_value=10, value=6,
            help="Users above this threshold are flagged as high-risk"
        )
    
    with col2:
        behavior_metrics = st.multiselect(
            "Behavior Metrics",
            ["Login Patterns", "Data Access", "Application Usage", "Network Activity", "File Operations"],
            default=["Login Patterns", "Data Access"]
        )
        
        if st.button("Run Behavior Analysis"):
            run_behavior_analysis(analysis_period, behavior_metrics)
    
    # High-risk users dashboard
    st.subheader("⚠️ High-Risk Users")
    
    high_risk_users = generate_high_risk_users()
    
    for _, user in high_risk_users.iterrows():
        risk_color = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡"
        }.get(user['Risk_Level'], "🔵")
        
        with st.expander(f"{risk_color} {user['Username']} ({user['Department']}) - Risk Score: {user['Risk_Score']}/10"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Role:** {user['Role']}")
                st.write(f"**Last Login:** {user['Last_Login']}")
                st.write(f"**Login Frequency:** {user['Login_Frequency']}")
                st.write(f"**Data Access Volume:** {user['Data_Access']}")
            
            with col2:
                st.write(f"**Unusual Activities:** {user['Unusual_Activities']}")
                st.write(f"**Policy Violations:** {user['Policy_Violations']}")
                st.write(f"**Network Usage:** {user['Network_Usage']}")
                st.write(f"**File Operations:** {user['File_Operations']}")
            
            st.write(f"**Risk Factors:** {user['Risk_Factors']}")
            
            # User activity timeline
            if st.button(f"View Activity Timeline", key=f"timeline_{user.name}"):
                show_user_timeline(user['Username'])
            
            # Action buttons
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button(f"Investigate User", key=f"investigate_{user.name}"):
                    investigate_user(user)
            
            with col2:
                if st.button(f"Restrict Access", key=f"restrict_{user.name}"):
                    st.warning(f"Access restrictions applied to {user['Username']}")
            
            with col3:
                if st.button(f"Mark as Reviewed", key=f"reviewed_{user.name}"):
                    st.success(f"User {user['Username']} marked as reviewed")
    
    # User behavior patterns
    st.subheader("📊 Behavior Pattern Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Login pattern analysis
        login_data = generate_login_patterns()
        fig = create_login_heatmap(login_data)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Data access patterns
        access_data = generate_access_patterns()
        fig = px.bar(access_data, x='Department', y='Data_Access_Volume',
                     color='Risk_Level', title="Data Access by Department")
        st.plotly_chart(fig, use_container_width=True)
    
    # Insider threat detection
    st.subheader("🕵️ Insider Threat Detection")
    
    threat_indicators = detect_insider_threats()
    
    for indicator in threat_indicators:
        severity_color = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }.get(indicator['severity'], "🔵")
        
        st.write(f"{severity_color} **{indicator['type']}** - {indicator['description']}")
        st.write(f"   Affected Users: {indicator['users']}, Confidence: {indicator['confidence']}")
    
    # User privilege analysis
    st.subheader("🔑 User Privilege Analysis")
    
    privilege_data = analyze_user_privileges()
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Privilege distribution
        fig = px.pie(values=privilege_data['counts'], names=privilege_data['levels'],
                     title="User Privilege Distribution")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Excessive privileges
        st.write("**Users with Excessive Privileges:**")
        excessive_privileges = get_excessive_privileges()
        for user in excessive_privileges:
            st.write(f"• {user['username']} ({user['role']}) - {user['excessive_perms']} unnecessary permissions")
    
    # Compliance and policy monitoring
    st.subheader("📋 Compliance & Policy Monitoring")
    
    compliance_status = get_compliance_status()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Policy Compliance", f"{compliance_status['overall']}%", delta="+2%")
    
    with col2:
        st.metric("Failed Logins Today", compliance_status['failed_logins'], delta="-15")
    
    with col3:
        st.metric("After-Hours Access", compliance_status['after_hours'], delta="+8")
    
    # Recent policy violations
    st.write("**Recent Policy Violations:**")
    violations = get_recent_violations()
    for violation in violations:
        st.write(f"• {violation['user']} - {violation['policy']} ({violation['time']})")

def run_behavior_analysis(period, metrics):
    """Run user behavior analysis"""
    with st.spinner(f"Analyzing user behavior for {period} across {len(metrics)} metrics..."):
        progress = st.progress(0)
        for i in range(100):
            progress.progress(i + 1)
        
        st.success(f"Behavior analysis completed! Found 7 anomalies and 3 high-risk users.")

def generate_high_risk_users():
    """Generate high-risk user data"""
    departments = ['IT', 'Finance', 'HR', 'Sales', 'Operations', 'R&D']
    roles = ['Manager', 'Analyst', 'Developer', 'Administrator', 'Specialist']
    risk_levels = ['Critical', 'High', 'Medium']
    
    risk_factors_list = [
        'Unusual login times, Excessive data downloads',
        'Failed authentication attempts, Policy violations',
        'After-hours access, Suspicious file operations',
        'Abnormal network traffic, Unauthorized access attempts',
        'Data exfiltration patterns, Privilege escalation'
    ]
    
    data = []
    for i in range(8):
        risk_level = np.random.choice(risk_levels, p=[0.2, 0.5, 0.3])
        risk_score = {'Critical': np.random.randint(8, 11), 
                     'High': np.random.randint(6, 9), 
                     'Medium': np.random.randint(4, 7)}[risk_level]
        
        data.append({
            'Username': f'user{i+1:03d}',
            'Department': np.random.choice(departments),
            'Role': np.random.choice(roles),
            'Risk_Level': risk_level,
            'Risk_Score': risk_score,
            'Last_Login': (datetime.now() - timedelta(hours=np.random.randint(1, 72))).strftime("%Y-%m-%d %H:%M"),
            'Login_Frequency': f"{np.random.randint(5, 50)} logins/day",
            'Data_Access': f"{np.random.randint(100, 5000)} MB/day",
            'Unusual_Activities': np.random.randint(1, 15),
            'Policy_Violations': np.random.randint(0, 8),
            'Network_Usage': f"{np.random.randint(500, 10000)} MB/day",
            'File_Operations': f"{np.random.randint(50, 500)} operations/day",
            'Risk_Factors': np.random.choice(risk_factors_list)
        })
    
    return pd.DataFrame(data)

def show_user_timeline(username):
    """Show user activity timeline"""
    st.subheader(f"📅 Activity Timeline for {username}")
    
    # Generate timeline data
    activities = [
        {'time': '09:15', 'activity': 'Login from office network', 'risk': 'Low'},
        {'time': '09:30', 'activity': 'Accessed customer database', 'risk': 'Medium'},
        {'time': '11:45', 'activity': 'Downloaded sensitive files', 'risk': 'High'},
        {'time': '14:20', 'activity': 'Failed VPN connection attempt', 'risk': 'Medium'},
        {'time': '17:30', 'activity': 'After-hours system access', 'risk': 'High'},
        {'time': '18:45', 'activity': 'Large file transfer initiated', 'risk': 'Critical'}
    ]
    
    for activity in activities:
        risk_color = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢'
        }.get(activity['risk'], '🔵')
        
        st.write(f"{activity['time']} - {risk_color} {activity['activity']}")

def investigate_user(user):
    """Show user investigation details"""
    st.info(f"**Investigation Report for {user['Username']}**")
    
    investigation_details = {
        "Account Created": "2022-03-15",
        "Last Password Change": "2024-01-10",
        "Failed Login Attempts": "12 in last 30 days",
        "Data Access History": "Accessed 45 sensitive files this month",
        "Network Connections": "3 unusual external connections detected",
        "Device Information": "Windows 10, Chrome browser, Office VPN",
        "Behavioral Score": f"{user['Risk_Score']}/10 (Above normal threshold)",
        "Recommended Actions": "Temporary access restriction, mandatory security training"
    }
    
    for key, value in investigation_details.items():
        st.write(f"**{key}:** {value}")

def generate_login_patterns():
    """Generate login pattern data for heatmap"""
    hours = range(24)
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    
    # Generate realistic login patterns (higher during business hours)
    login_counts = []
    for day in days:
        for hour in hours:
            if day in ['Saturday', 'Sunday']:
                # Weekend pattern - lower activity
                base_count = 2
            else:
                # Weekday pattern - higher during business hours
                if 9 <= hour <= 17:
                    base_count = 25
                elif 8 <= hour <= 19:
                    base_count = 15
                else:
                    base_count = 5
            
            # Add some randomness
            count = max(0, base_count + np.random.randint(-5, 6))
            login_counts.append({'Day': day, 'Hour': hour, 'Logins': count})
    
    return pd.DataFrame(login_counts)

def create_login_heatmap(data):
    """Create login pattern heatmap"""
    pivot_data = data.pivot(index='Day', columns='Hour', values='Logins')
    
    fig = px.imshow(pivot_data, 
                    title="Login Patterns - Day vs Hour Heatmap",
                    labels={'x': 'Hour of Day', 'y': 'Day of Week', 'color': 'Login Count'},
                    color_continuous_scale='Viridis')
    
    return fig

def generate_access_patterns():
    """Generate data access patterns by department"""
    departments = ['IT', 'Finance', 'HR', 'Sales', 'Operations', 'R&D']
    risk_levels = ['Low', 'Medium', 'High', 'Critical']
    
    data = []
    for dept in departments:
        for risk in risk_levels:
            # Different departments have different typical access volumes
            base_volume = {
                'IT': 5000, 'Finance': 3000, 'HR': 2000,
                'Sales': 1500, 'Operations': 2500, 'R&D': 4000
            }[dept]
            
            # Risk level affects volume
            risk_multiplier = {'Low': 1, 'Medium': 1.5, 'High': 2.5, 'Critical': 4}[risk]
            
            volume = int(base_volume * risk_multiplier * np.random.uniform(0.5, 1.5))
            
            data.append({
                'Department': dept,
                'Risk_Level': risk,
                'Data_Access_Volume': volume
            })
    
    return pd.DataFrame(data)

def detect_insider_threats():
    """Detect potential insider threats"""
    threats = [
        {
            'type': 'Data Hoarding',
            'severity': 'High',
            'description': 'Users downloading excessive amounts of sensitive data',
            'users': 'user045, user128, user201',
            'confidence': '89%'
        },
        {
            'type': 'After-Hours Access',
            'severity': 'Medium',
            'description': 'Unusual access patterns outside business hours',
            'users': 'user067, user143',
            'confidence': '76%'
        },
        {
            'type': 'Privilege Abuse',
            'severity': 'Critical',
            'description': 'Users accessing data outside their role requirements',
            'users': 'user089',
            'confidence': '94%'
        },
        {
            'type': 'Anomalous Network Activity',
            'severity': 'High',
            'description': 'Unusual external network connections',
            'users': 'user156, user234',
            'confidence': '82%'
        }
    ]
    
    return threats

def analyze_user_privileges():
    """Analyze user privilege distribution"""
    return {
        'levels': ['Standard User', 'Power User', 'Administrator', 'Super Admin'],
        'counts': [180, 45, 18, 4]
    }

def get_excessive_privileges():
    """Get users with excessive privileges"""
    return [
        {'username': 'user045', 'role': 'Marketing Analyst', 'excessive_perms': 8},
        {'username': 'user128', 'role': 'Sales Rep', 'excessive_perms': 12},
        {'username': 'user201', 'role': 'HR Specialist', 'excessive_perms': 6},
        {'username': 'user156', 'role': 'Finance Clerk', 'excessive_perms': 15}
    ]

def get_compliance_status():
    """Get compliance monitoring status"""
    return {
        'overall': 87,
        'failed_logins': 156,
        'after_hours': 23
    }

def get_recent_violations():
    """Get recent policy violations"""
    return [
        {'user': 'user089', 'policy': 'Data Access Policy', 'time': '2 hours ago'},
        {'user': 'user156', 'policy': 'Password Policy', 'time': '4 hours ago'},
        {'user': 'user234', 'policy': 'Network Usage Policy', 'time': '6 hours ago'},
        {'user': 'user045', 'policy': 'After-Hours Access Policy', 'time': '8 hours ago'}
    ]
