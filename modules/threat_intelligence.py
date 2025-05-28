import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import os

def show_threat_intelligence():
    """Threat intelligence aggregation and visualization"""
    st.header("🌍 Threat Intelligence & External Feeds")
    
    # Threat intelligence metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Active IOCs", "1,247", delta="+89")
    with col2:
        st.metric("Threat Feeds", "12", delta="+2")
    with col3:
        st.metric("New Campaigns", "8", delta="+3")
    with col4:
        st.metric("Intelligence Score", "8.7/10", delta="+0.3")
    
    st.divider()
    
    # Threat intelligence configuration
    st.subheader("⚙️ Intelligence Feed Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        feed_sources = st.multiselect(
            "Active Threat Feeds",
            ["MISP", "AlienVault OTX", "VirusTotal", "IBM X-Force", "Recorded Future", 
             "ThreatConnect", "Anomali", "CrowdStrike", "FireEye", "Mandiant"],
            default=["MISP", "AlienVault OTX", "VirusTotal"]
        )
        
        update_frequency = st.selectbox(
            "Update Frequency",
            ["Real-time", "Every 15 minutes", "Hourly", "Daily"]
        )
    
    with col2:
        intelligence_types = st.multiselect(
            "Intelligence Types",
            ["Malware Indicators", "IP Addresses", "Domains", "URLs", "File Hashes", 
             "Email Addresses", "Attack Patterns", "Vulnerabilities"],
            default=["Malware Indicators", "IP Addresses", "Domains"]
        )
        
        if st.button("Update Intelligence Feeds"):
            update_threat_feeds(feed_sources, intelligence_types)
    
    # Current threat landscape
    st.subheader("🎯 Current Threat Landscape")
    
    threat_landscape = get_threat_landscape()
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat actor activity
        st.write("**Top Active Threat Actors:**")
        for actor in threat_landscape['actors']:
            risk_color = "🔴" if actor['risk'] == "High" else "🟡" if actor['risk'] == "Medium" else "🟢"
            st.write(f"{risk_color} **{actor['name']}** - {actor['activity']}")
            st.write(f"   Targeting: {actor['targets']}, TTPs: {actor['ttps']}")
    
    with col2:
        # Malware families
        st.write("**Active Malware Families:**")
        for malware in threat_landscape['malware']:
            st.write(f"🦠 **{malware['family']}** - {malware['type']}")
            st.write(f"   Prevalence: {malware['prevalence']}, Last seen: {malware['last_seen']}")
    
    # Indicators of Compromise (IOCs)
    st.subheader("🔍 Indicators of Compromise (IOCs)")
    
    # IOC filtering
    col1, col2, col3 = st.columns(3)
    
    with col1:
        ioc_type_filter = st.selectbox(
            "IOC Type",
            ["All", "IP Address", "Domain", "URL", "File Hash", "Email"]
        )
    
    with col2:
        confidence_filter = st.slider(
            "Minimum Confidence",
            min_value=0, max_value=100, value=70
        )
    
    with col3:
        age_filter = st.selectbox(
            "Age Filter",
            ["All", "Last 24 hours", "Last week", "Last month"]
        )
    
    # Generate and display IOCs
    iocs = generate_ioc_data()
    filtered_iocs = apply_ioc_filters(iocs, ioc_type_filter, confidence_filter, age_filter)
    
    # IOC data table
    st.dataframe(
        filtered_iocs[['IOC', 'Type', 'Threat_Type', 'Confidence', 'Source', 'First_Seen']],
        use_container_width=True
    )
    
    # IOC analysis and enrichment
    if not filtered_iocs.empty:
        selected_ioc = st.selectbox(
            "Select IOC for detailed analysis:",
            filtered_iocs['IOC'].tolist()
        )
        
        if selected_ioc:
            show_ioc_analysis(selected_ioc, filtered_iocs)
    
    # Threat campaigns and attribution
    st.subheader("🎭 Threat Campaigns & Attribution")
    
    campaigns = get_active_campaigns()
    
    for campaign in campaigns:
        with st.expander(f"🎯 {campaign['name']} - {campaign['status']}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Attributed to:** {campaign['attribution']}")
                st.write(f"**First Observed:** {campaign['first_observed']}")
                st.write(f"**Target Sectors:** {campaign['targets']}")
                st.write(f"**Geographic Focus:** {campaign['geography']}")
            
            with col2:
                st.write(f"**Attack Vectors:** {campaign['vectors']}")
                st.write(f"**Malware Used:** {campaign['malware']}")
                st.write(f"**Confidence Level:** {campaign['confidence']}")
                st.write(f"**Risk Level:** {campaign['risk']}")
            
            st.write(f"**Description:** {campaign['description']}")
            
            # Campaign timeline
            if st.button(f"View Campaign Timeline", key=f"timeline_{campaign['id']}"):
                show_campaign_timeline(campaign['name'])
    
    # Vulnerability intelligence
    st.subheader("🔓 Vulnerability Intelligence")
    
    vulnerabilities = get_vulnerability_intelligence()
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Critical vulnerabilities
        st.write("**Critical Vulnerabilities:**")
        for vuln in vulnerabilities['critical']:
            st.write(f"🔴 **{vuln['cve']}** - CVSS {vuln['cvss']}")
            st.write(f"   {vuln['description']}")
            st.write(f"   Exploitation: {vuln['exploitation']}")
    
    with col2:
        # Vulnerability trends
        vuln_data = generate_vulnerability_trends()
        fig = px.line(vuln_data, x='Date', y='Count', color='Severity',
                     title="Vulnerability Disclosure Trends")
        st.plotly_chart(fig, use_container_width=True)
    
    # Threat intelligence analytics
    st.subheader("📊 Intelligence Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # IOC type distribution
        ioc_types = iocs['Type'].value_counts()
        fig = px.pie(values=ioc_types.values, names=ioc_types.index,
                     title="IOC Distribution by Type")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Threat confidence levels
        confidence_ranges = pd.cut(iocs['Confidence'], bins=[0, 30, 60, 80, 100], 
                                 labels=['Low', 'Medium', 'High', 'Very High'])
        confidence_counts = confidence_ranges.value_counts()
        fig = px.bar(x=confidence_counts.index, y=confidence_counts.values,
                     title="IOC Confidence Distribution")
        st.plotly_chart(fig, use_container_width=True)
    
    # Threat hunting suggestions
    st.subheader("🕵️ Threat Hunting Suggestions")
    
    hunting_queries = generate_hunting_queries()
    
    for query in hunting_queries:
        with st.expander(f"🔍 {query['title']} - {query['priority']} Priority"):
            st.write(f"**Technique:** {query['technique']}")
            st.write(f"**Data Sources:** {query['data_sources']}")
            st.write(f"**Query:** `{query['query']}`")
            st.write(f"**Description:** {query['description']}")
            
            if st.button(f"Execute Hunt", key=f"hunt_{query['id']}"):
                execute_threat_hunt(query)
    
    # Intelligence sharing and collaboration
    st.subheader("🤝 Intelligence Sharing")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Sharing Communities:**")
        communities = get_sharing_communities()
        for community in communities:
            status_icon = "🟢" if community['status'] == "Active" else "🔴"
            st.write(f"{status_icon} {community['name']} - {community['members']} members")
    
    with col2:
        st.write("**Recent Contributions:**")
        contributions = get_recent_contributions()
        for contrib in contributions:
            st.write(f"📤 {contrib['type']}: {contrib['description']}")
            st.write(f"   Shared with: {contrib['community']}")

def update_threat_feeds(sources, intel_types):
    """Update threat intelligence feeds"""
    with st.spinner(f"Updating {len(sources)} threat feeds..."):
        progress = st.progress(0)
        for i in range(100):
            progress.progress(i + 1)
        
        st.success(f"Updated {len(sources)} feeds with {len(intel_types)} intelligence types. Found 234 new IOCs.")

def get_threat_landscape():
    """Get current threat landscape data"""
    return {
        'actors': [
            {
                'name': 'APT29 (Cozy Bear)',
                'activity': 'Espionage campaigns targeting government',
                'targets': 'Government, Healthcare',
                'ttps': 'Spear-phishing, Living-off-the-land',
                'risk': 'High'
            },
            {
                'name': 'Lazarus Group',
                'activity': 'Financial institution attacks',
                'targets': 'Banking, Cryptocurrency',
                'ttps': 'Supply chain attacks, Custom malware',
                'risk': 'High'
            },
            {
                'name': 'Carbanak',
                'activity': 'Banking trojans and ATM attacks',
                'targets': 'Financial services',
                'ttps': 'Banking trojans, ATM manipulation',
                'risk': 'Medium'
            }
        ],
        'malware': [
            {
                'family': 'Emotet',
                'type': 'Banking Trojan',
                'prevalence': 'High',
                'last_seen': '2 days ago'
            },
            {
                'family': 'TrickBot',
                'type': 'Modular Trojan',
                'prevalence': 'Medium',
                'last_seen': '1 week ago'
            },
            {
                'family': 'Ryuk',
                'type': 'Ransomware',
                'prevalence': 'Medium',
                'last_seen': '3 days ago'
            }
        ]
    }

def generate_ioc_data():
    """Generate IOC data"""
    ioc_types = ['IP Address', 'Domain', 'URL', 'File Hash', 'Email']
    threat_types = ['Malware', 'Phishing', 'C2', 'Exploit Kit', 'Ransomware']
    sources = ['MISP', 'AlienVault OTX', 'VirusTotal', 'IBM X-Force', 'Manual Analysis']
    
    data = []
    for i in range(50):
        ioc_type = np.random.choice(ioc_types)
        
        # Generate realistic IOCs based on type
        if ioc_type == 'IP Address':
            ioc = f"{np.random.randint(1, 256)}.{np.random.randint(1, 256)}.{np.random.randint(1, 256)}.{np.random.randint(1, 256)}"
        elif ioc_type == 'Domain':
            domains = ['malicious-site.com', 'bad-domain.net', 'evil-server.org', 'threat-actor.biz']
            ioc = np.random.choice(domains)
        elif ioc_type == 'URL':
            ioc = f"http://suspicious-{np.random.randint(1, 1000)}.com/malware.exe"
        elif ioc_type == 'File Hash':
            ioc = ''.join(np.random.choice('0123456789abcdef', 64))
        else:  # Email
            ioc = f"phishing{np.random.randint(1, 100)}@malicious-domain.com"
        
        data.append({
            'IOC': ioc,
            'Type': ioc_type,
            'Threat_Type': np.random.choice(threat_types),
            'Confidence': np.random.randint(30, 100),
            'Source': np.random.choice(sources),
            'First_Seen': (datetime.now() - timedelta(days=np.random.randint(0, 30))).strftime("%Y-%m-%d"),
            'Tags': ', '.join(np.random.choice(['banking', 'apt', 'ransomware', 'phishing', 'c2'], 
                                            size=np.random.randint(1, 3), replace=False))
        })
    
    return pd.DataFrame(data)

def apply_ioc_filters(data, ioc_type_filter, confidence_filter, age_filter):
    """Apply filters to IOC data"""
    filtered_data = data.copy()
    
    if ioc_type_filter != "All":
        filtered_data = filtered_data[filtered_data['Type'] == ioc_type_filter]
    
    filtered_data = filtered_data[filtered_data['Confidence'] >= confidence_filter]
    
    # Age filtering would be implemented here based on actual dates
    
    return filtered_data

def show_ioc_analysis(selected_ioc, iocs_data):
    """Show detailed IOC analysis"""
    ioc_data = iocs_data[iocs_data['IOC'] == selected_ioc].iloc[0]
    
    st.subheader(f"🔍 IOC Analysis: {selected_ioc}")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Type:** {ioc_data['Type']}")
        st.write(f"**Threat Type:** {ioc_data['Threat_Type']}")
        st.write(f"**Confidence:** {ioc_data['Confidence']}%")
        st.write(f"**Source:** {ioc_data['Source']}")
        st.write(f"**First Seen:** {ioc_data['First_Seen']}")
        st.write(f"**Tags:** {ioc_data['Tags']}")
    
    with col2:
        # Enrichment data (simulated)
        enrichment = {
            'Geolocation': 'Russia (Moscow)',
            'ASN': 'AS12345 - Suspicious Hosting Ltd',
            'Reputation Score': '2/10 (Very Malicious)',
            'Related Campaigns': 'APT29, Lazarus Group',
            'Malware Families': 'Emotet, TrickBot',
            'Last Active': '2 hours ago'
        }
        
        for key, value in enrichment.items():
            st.write(f"**{key}:** {value}")
    
    # External lookups
    if st.button("Lookup in VirusTotal"):
        st.info("VirusTotal lookup initiated...")
    
    if st.button("Check Reputation"):
        st.info("Reputation check in progress...")

def get_active_campaigns():
    """Get active threat campaigns"""
    return [
        {
            'id': 1,
            'name': 'Operation SolarFlare',
            'status': 'Active',
            'attribution': 'APT29 (Cozy Bear)',
            'first_observed': '2024-01-10',
            'targets': 'Government, Technology',
            'geography': 'United States, Europe',
            'vectors': 'Supply Chain, Spear-phishing',
            'malware': 'SUNBURST, TEARDROP',
            'confidence': 'High (90%)',
            'risk': 'Critical',
            'description': 'Sophisticated supply chain attack targeting software vendors and their customers.'
        },
        {
            'id': 2,
            'name': 'BankHeist Campaign',
            'status': 'Ongoing',
            'attribution': 'Carbanak Group',
            'first_observed': '2024-01-15',
            'targets': 'Financial Services',
            'geography': 'Global',
            'vectors': 'Banking Trojans, ATM Attacks',
            'malware': 'Carbanak, Cobalt Strike',
            'confidence': 'Medium (75%)',
            'risk': 'High',
            'description': 'Large-scale financial fraud campaign targeting multiple banking institutions.'
        }
    ]

def show_campaign_timeline(campaign_name):
    """Show campaign timeline"""
    st.subheader(f"📅 {campaign_name} Timeline")
    
    timeline_events = [
        {'date': '2024-01-10', 'event': 'Initial compromise detected'},
        {'date': '2024-01-12', 'event': 'Lateral movement observed'},
        {'date': '2024-01-15', 'event': 'Data exfiltration attempt'},
        {'date': '2024-01-18', 'event': 'Secondary payload deployment'},
        {'date': '2024-01-20', 'event': 'Command and control established'},
        {'date': '2024-01-22', 'event': 'Persistence mechanisms installed'}
    ]
    
    for event in timeline_events:
        st.write(f"**{event['date']}:** {event['event']}")

def get_vulnerability_intelligence():
    """Get vulnerability intelligence data"""
    return {
        'critical': [
            {
                'cve': 'CVE-2024-0001',
                'cvss': '9.8',
                'description': 'Remote code execution in popular web framework',
                'exploitation': 'Active exploitation detected'
            },
            {
                'cve': 'CVE-2024-0002',
                'cvss': '9.1',
                'description': 'Privilege escalation in operating system kernel',
                'exploitation': 'Proof-of-concept available'
            },
            {
                'cve': 'CVE-2024-0003',
                'cvss': '8.9',
                'description': 'SQL injection in enterprise application',
                'exploitation': 'Mass scanning observed'
            }
        ]
    }

def generate_vulnerability_trends():
    """Generate vulnerability trend data"""
    dates = pd.date_range(start=datetime.now() - timedelta(days=30), 
                         end=datetime.now(), freq='D')
    
    severities = ['Critical', 'High', 'Medium', 'Low']
    data = []
    
    for date in dates:
        for severity in severities:
            base_count = {'Critical': 1, 'High': 3, 'Medium': 8, 'Low': 15}[severity]
            count = max(0, int(base_count + np.random.normal(0, 2)))
            
            data.append({
                'Date': date,
                'Severity': severity,
                'Count': count
            })
    
    return pd.DataFrame(data)

def generate_hunting_queries():
    """Generate threat hunting query suggestions"""
    return [
        {
            'id': 1,
            'title': 'Suspicious PowerShell Activity',
            'priority': 'High',
            'technique': 'T1059.001 - PowerShell',
            'data_sources': 'Windows Event Logs, EDR',
            'query': 'process_name:"powershell.exe" AND (command_line:*-EncodedCommand* OR command_line:*-WindowStyle Hidden*)',
            'description': 'Detect potentially malicious PowerShell commands with encoding or hidden windows'
        },
        {
            'id': 2,
            'title': 'Unusual Network Connections',
            'priority': 'Medium',
            'technique': 'T1071 - Application Layer Protocol',
            'data_sources': 'Network logs, Firewall',
            'query': 'dst_port:8080 OR dst_port:8443 OR dst_port:9999',
            'description': 'Look for connections to uncommon ports that might indicate C2 communication'
        },
        {
            'id': 3,
            'title': 'Credential Dumping Tools',
            'priority': 'Critical',
            'technique': 'T1003 - OS Credential Dumping',
            'data_sources': 'EDR, Process logs',
            'query': 'process_name:(mimikatz.exe OR procdump.exe OR lsass.exe) OR command_line:*sekurlsa*',
            'description': 'Detect tools commonly used for credential dumping'
        }
    ]

def execute_threat_hunt(query):
    """Execute threat hunting query"""
    st.info(f"Executing hunt: {query['title']}")
    
    # Simulate hunt results
    results = {
        'matches': np.random.randint(0, 50),
        'false_positives': np.random.randint(0, 10),
        'investigation_required': np.random.randint(0, 5)
    }
    
    if results['matches'] > 0:
        st.warning(f"Found {results['matches']} potential matches!")
        st.write(f"False positives: {results['false_positives']}")
        st.write(f"Require investigation: {results['investigation_required']}")
    else:
        st.success("No suspicious activity detected")

def get_sharing_communities():
    """Get threat intelligence sharing communities"""
    return [
        {'name': 'Industry ISAC', 'status': 'Active', 'members': 247},
        {'name': 'Regional Threat Share', 'status': 'Active', 'members': 89},
        {'name': 'Malware Research Group', 'status': 'Active', 'members': 156},
        {'name': 'Vulnerability Exchange', 'status': 'Inactive', 'members': 45}
    ]

def get_recent_contributions():
    """Get recent intelligence contributions"""
    return [
        {
            'type': 'IOC Package',
            'description': '45 new malware hashes from recent campaign',
            'community': 'Industry ISAC'
        },
        {
            'type': 'YARA Rules',
            'description': 'Detection rules for new ransomware variant',
            'community': 'Malware Research Group'
        },
        {
            'type': 'TTPs Analysis',
            'description': 'Behavioral analysis of APT group tactics',
            'community': 'Regional Threat Share'
        }
    ]
