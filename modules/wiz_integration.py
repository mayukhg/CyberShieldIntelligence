"""
Wiz Security Platform Integration
Connects to Wiz API to fetch cloud security findings, vulnerabilities, and compliance data
"""

import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import os
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WizConnector:
    """Wiz API connector for fetching security data"""
    
    def __init__(self):
        self.base_url = "https://api.wiz.io"
        self.api_token = os.getenv('WIZ_API_TOKEN')
        self.client_id = os.getenv('WIZ_CLIENT_ID')
        self.client_secret = os.getenv('WIZ_CLIENT_SECRET')
        self.session = requests.Session()
        
        if self.api_token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json'
            })
    
    def authenticate(self) -> bool:
        """Authenticate with Wiz API using client credentials"""
        if not self.client_id or not self.client_secret:
            return False
            
        try:
            auth_url = f"{self.base_url}/oauth/token"
            auth_data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'audience': 'wiz-api'
            }
            
            response = requests.post(auth_url, json=auth_data)
            if response.status_code == 200:
                token_data = response.json()
                self.api_token = token_data.get('access_token')
                self.session.headers.update({
                    'Authorization': f'Bearer {self.api_token}',
                    'Content-Type': 'application/json'
                })
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return False
    
    def get_issues(self, severity: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch security issues from Wiz"""
        if not self.api_token:
            return []
            
        try:
            url = f"{self.base_url}/v1/issues"
            params = {'limit': limit}
            if severity:
                params['severity'] = severity
                
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                return response.json().get('data', [])
            else:
                logger.error(f"Failed to fetch issues: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching issues: {str(e)}")
            return []
    
    def get_vulnerabilities(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from Wiz"""
        if not self.api_token:
            return []
            
        try:
            url = f"{self.base_url}/v1/vulnerabilities"
            params = {'limit': limit}
            
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                return response.json().get('data', [])
            else:
                logger.error(f"Failed to fetch vulnerabilities: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities: {str(e)}")
            return []
    
    def get_cloud_assets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch cloud assets from Wiz"""
        if not self.api_token:
            return []
            
        try:
            url = f"{self.base_url}/v1/assets"
            params = {'limit': limit}
            
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                return response.json().get('data', [])
            else:
                logger.error(f"Failed to fetch assets: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching assets: {str(e)}")
            return []
    
    def get_compliance_findings(self, framework: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch compliance findings from Wiz"""
        if not self.api_token:
            return []
            
        try:
            url = f"{self.base_url}/v1/compliance/findings"
            params = {'limit': limit}
            if framework:
                params['framework'] = framework
                
            response = self.session.get(url, params=params)
            if response.status_code == 200:
                return response.json().get('data', [])
            else:
                logger.error(f"Failed to fetch compliance findings: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching compliance findings: {str(e)}")
            return []

def show_wiz_integration():
    """Main Wiz integration dashboard"""
    st.header("🔮 Wiz Security Platform Integration")
    st.markdown("Connect to Wiz for comprehensive cloud security monitoring and vulnerability management")
    
    # Configuration section
    with st.expander("🔧 Wiz Configuration", expanded=False):
        st.markdown("### API Configuration")
        
        col1, col2 = st.columns(2)
        with col1:
            st.text_input("Wiz API Endpoint", value="https://api.wiz.io", disabled=True)
            wiz_client_id = st.text_input("Client ID", type="password", help="Your Wiz Client ID")
        
        with col2:
            st.text_input("Authentication Method", value="OAuth 2.0", disabled=True)
            wiz_client_secret = st.text_input("Client Secret", type="password", help="Your Wiz Client Secret")
        
        if st.button("🔗 Test Connection"):
            if wiz_client_id and wiz_client_secret:
                # Store credentials temporarily for testing
                os.environ['WIZ_CLIENT_ID'] = wiz_client_id
                os.environ['WIZ_CLIENT_SECRET'] = wiz_client_secret
                
                wiz = WizConnector()
                if wiz.authenticate():
                    st.success("✅ Successfully connected to Wiz API!")
                else:
                    st.error("❌ Failed to connect to Wiz API. Please check your credentials.")
            else:
                st.warning("Please provide both Client ID and Client Secret")
    
    # Check if we have valid credentials
    wiz = WizConnector()
    has_credentials = bool(wiz.client_id and wiz.client_secret)
    
    if not has_credentials:
        st.warning("⚠️ Wiz API credentials not configured. Please set up your credentials above to fetch live data.")
        st.info("To get your Wiz API credentials:\n1. Log in to your Wiz console\n2. Go to Settings > Service Accounts\n3. Create a new service account with appropriate permissions\n4. Copy the Client ID and Client Secret")
        return
    
    # Authenticate and fetch data
    if not wiz.authenticate():
        st.error("Failed to authenticate with Wiz API. Please check your credentials.")
        return
    
    # Main dashboard tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Overview", 
        "🚨 Security Issues", 
        "🔍 Vulnerabilities", 
        "☁️ Cloud Assets", 
        "📋 Compliance"
    ])
    
    with tab1:
        show_wiz_overview(wiz)
    
    with tab2:
        show_security_issues(wiz)
    
    with tab3:
        show_vulnerabilities(wiz)
    
    with tab4:
        show_cloud_assets(wiz)
    
    with tab5:
        show_compliance_dashboard(wiz)

def show_wiz_overview(wiz: WizConnector):
    """Show Wiz security overview dashboard"""
    st.subheader("🎯 Wiz Security Overview")
    
    # Fetch summary data
    issues = wiz.get_issues(limit=50)
    vulnerabilities = wiz.get_vulnerabilities(limit=50)
    assets = wiz.get_cloud_assets(limit=50)
    compliance = wiz.get_compliance_findings(limit=50)
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        critical_issues = len([i for i in issues if i.get('severity') == 'CRITICAL'])
        st.metric("Critical Issues", critical_issues, delta=None)
    
    with col2:
        high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        st.metric("High Vulnerabilities", high_vulns, delta=None)
    
    with col3:
        st.metric("Total Assets", len(assets), delta=None)
    
    with col4:
        failed_compliance = len([c for c in compliance if c.get('status') == 'FAILED'])
        st.metric("Compliance Failures", failed_compliance, delta=None)
    
    # Security posture chart
    if issues:
        st.subheader("📈 Security Issue Trends")
        
        # Create severity distribution
        severity_counts = {}
        for issue in issues:
            severity = issue.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            fig = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                title="Security Issues by Severity",
                color_discrete_map={
                    'CRITICAL': '#ff4444',
                    'HIGH': '#ff8800',
                    'MEDIUM': '#ffbb00',
                    'LOW': '#00aa00',
                    'INFORMATIONAL': '#0088ff'
                }
            )
            st.plotly_chart(fig, use_container_width=True)

def show_security_issues(wiz: WizConnector):
    """Show security issues from Wiz"""
    st.subheader("🚨 Security Issues")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        severity_filter = st.selectbox("Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col2:
        status_filter = st.selectbox("Status", ["All", "OPEN", "RESOLVED", "SUPPRESSED"])
    with col3:
        limit = st.slider("Max Results", 10, 200, 50)
    
    # Fetch issues
    issues = wiz.get_issues(limit=limit)
    
    if not issues:
        st.info("No security issues found or unable to fetch data from Wiz.")
        return
    
    # Filter issues
    filtered_issues = issues
    if severity_filter != "All":
        filtered_issues = [i for i in filtered_issues if i.get('severity') == severity_filter]
    if status_filter != "All":
        filtered_issues = [i for i in filtered_issues if i.get('status') == status_filter]
    
    # Display issues
    st.write(f"Found **{len(filtered_issues)}** security issues")
    
    for issue in filtered_issues[:20]:  # Show top 20
        severity = issue.get('severity', 'UNKNOWN')
        severity_color = {
            'CRITICAL': '🔥',
            'HIGH': '🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFORMATIONAL': '🔵'
        }.get(severity, '⚪')
        
        with st.expander(f"{severity_color} {issue.get('title', 'Unknown Issue')} - {severity}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Resource:** {issue.get('resource', {}).get('name', 'Unknown')}")
                st.write(f"**Type:** {issue.get('type', 'Unknown')}")
                st.write(f"**Status:** {issue.get('status', 'Unknown')}")
            
            with col2:
                st.write(f"**Created:** {issue.get('createdAt', 'Unknown')}")
                st.write(f"**Updated:** {issue.get('updatedAt', 'Unknown')}")
                st.write(f"**Source:** {issue.get('source', 'Wiz')}")
            
            if issue.get('description'):
                st.write(f"**Description:** {issue.get('description')}")

def show_vulnerabilities(wiz: WizConnector):
    """Show vulnerabilities from Wiz"""
    st.subheader("🔍 Vulnerability Management")
    
    # Fetch vulnerabilities
    vulnerabilities = wiz.get_vulnerabilities(limit=100)
    
    if not vulnerabilities:
        st.info("No vulnerabilities found or unable to fetch data from Wiz.")
        return
    
    # Vulnerability statistics
    col1, col2, col3 = st.columns(3)
    
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'UNKNOWN')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    with col1:
        critical_vulns = severity_counts.get('CRITICAL', 0)
        st.metric("Critical Vulnerabilities", critical_vulns)
    
    with col2:
        high_vulns = severity_counts.get('HIGH', 0)
        st.metric("High Vulnerabilities", high_vulns)
    
    with col3:
        total_vulns = len(vulnerabilities)
        st.metric("Total Vulnerabilities", total_vulns)
    
    # Vulnerability list
    st.subheader("🎯 Top Vulnerabilities")
    
    for vuln in vulnerabilities[:15]:  # Show top 15
        severity = vuln.get('severity', 'UNKNOWN')
        cvss_score = vuln.get('cvssScore', 0)
        
        severity_color = {
            'CRITICAL': '🔥',
            'HIGH': '🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(severity, '⚪')
        
        with st.expander(f"{severity_color} {vuln.get('name', 'Unknown CVE')} - CVSS {cvss_score}"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**CVE ID:** {vuln.get('cveId', 'N/A')}")
                st.write(f"**CVSS Score:** {cvss_score}")
                st.write(f"**Severity:** {severity}")
            
            with col2:
                st.write(f"**Published:** {vuln.get('publishedDate', 'Unknown')}")
                st.write(f"**Vendor:** {vuln.get('vendor', 'Unknown')}")
                st.write(f"**Product:** {vuln.get('product', 'Unknown')}")
            
            if vuln.get('description'):
                st.write(f"**Description:** {vuln.get('description')}")

def show_cloud_assets(wiz: WizConnector):
    """Show cloud assets from Wiz"""
    st.subheader("☁️ Cloud Asset Inventory")
    
    # Fetch assets
    assets = wiz.get_cloud_assets(limit=100)
    
    if not assets:
        st.info("No cloud assets found or unable to fetch data from Wiz.")
        return
    
    # Asset statistics
    col1, col2, col3, col4 = st.columns(4)
    
    asset_types = {}
    cloud_providers = {}
    for asset in assets:
        asset_type = asset.get('type', 'Unknown')
        provider = asset.get('cloudProvider', 'Unknown')
        
        asset_types[asset_type] = asset_types.get(asset_type, 0) + 1
        cloud_providers[provider] = cloud_providers.get(provider, 0) + 1
    
    with col1:
        st.metric("Total Assets", len(assets))
    with col2:
        st.metric("Asset Types", len(asset_types))
    with col3:
        st.metric("Cloud Providers", len(cloud_providers))
    with col4:
        exposed_assets = len([a for a in assets if a.get('isPublic', False)])
        st.metric("Public Assets", exposed_assets)
    
    # Asset distribution charts
    col1, col2 = st.columns(2)
    
    with col1:
        if asset_types:
            fig = px.bar(
                x=list(asset_types.keys()),
                y=list(asset_types.values()),
                title="Assets by Type"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if cloud_providers:
            fig = px.pie(
                values=list(cloud_providers.values()),
                names=list(cloud_providers.keys()),
                title="Assets by Cloud Provider"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Asset details
    st.subheader("📋 Asset Details")
    
    for asset in assets[:20]:  # Show top 20
        risk_level = asset.get('riskLevel', 'UNKNOWN')
        risk_color = {
            'CRITICAL': '🔥',
            'HIGH': '🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(risk_level, '⚪')
        
        with st.expander(f"{risk_color} {asset.get('name', 'Unknown Asset')} ({asset.get('type', 'Unknown')})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Provider:** {asset.get('cloudProvider', 'Unknown')}")
                st.write(f"**Region:** {asset.get('region', 'Unknown')}")
                st.write(f"**Risk Level:** {risk_level}")
            
            with col2:
                st.write(f"**Public:** {'Yes' if asset.get('isPublic') else 'No'}")
                st.write(f"**Created:** {asset.get('createdAt', 'Unknown')}")
                st.write(f"**Project:** {asset.get('project', 'Unknown')}")

def show_compliance_dashboard(wiz: WizConnector):
    """Show compliance dashboard from Wiz"""
    st.subheader("📋 Compliance Dashboard")
    
    # Compliance framework selector
    framework = st.selectbox(
        "Compliance Framework",
        ["All", "SOC2", "ISO27001", "PCI-DSS", "HIPAA", "GDPR", "NIST"]
    )
    
    # Fetch compliance findings
    compliance_filter = None if framework == "All" else framework
    findings = wiz.get_compliance_findings(framework=compliance_filter, limit=100)
    
    if not findings:
        st.info("No compliance findings found or unable to fetch data from Wiz.")
        return
    
    # Compliance metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_findings = len(findings)
    passed_findings = len([f for f in findings if f.get('status') == 'PASSED'])
    failed_findings = len([f for f in findings if f.get('status') == 'FAILED'])
    compliance_score = (passed_findings / total_findings * 100) if total_findings > 0 else 0
    
    with col1:
        st.metric("Total Controls", total_findings)
    with col2:
        st.metric("Passed", passed_findings, delta=None)
    with col3:
        st.metric("Failed", failed_findings, delta=None)
    with col4:
        st.metric("Compliance Score", f"{compliance_score:.1f}%", delta=None)
    
    # Compliance status chart
    if findings:
        status_counts = {}
        for finding in findings:
            status = finding.get('status', 'UNKNOWN')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        fig = px.pie(
            values=list(status_counts.values()),
            names=list(status_counts.keys()),
            title=f"Compliance Status - {framework if framework != 'All' else 'All Frameworks'}",
            color_discrete_map={
                'PASSED': '#00aa00',
                'FAILED': '#ff4444',
                'WARNING': '#ffaa00',
                'NOT_APPLICABLE': '#888888'
            }
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Failed controls
    failed_controls = [f for f in findings if f.get('status') == 'FAILED']
    
    if failed_controls:
        st.subheader("❌ Failed Compliance Controls")
        
        for control in failed_controls[:10]:  # Show top 10 failed
            severity = control.get('severity', 'MEDIUM')
            severity_color = {
                'HIGH': '🔴',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(severity, '⚪')
            
            with st.expander(f"{severity_color} {control.get('control', 'Unknown Control')} - {control.get('framework', 'Unknown')}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Framework:** {control.get('framework', 'Unknown')}")
                    st.write(f"**Severity:** {severity}")
                    st.write(f"**Resource:** {control.get('resource', {}).get('name', 'Unknown')}")
                
                with col2:
                    st.write(f"**Last Checked:** {control.get('lastChecked', 'Unknown')}")
                    st.write(f"**Region:** {control.get('region', 'Unknown')}")
                    st.write(f"**Provider:** {control.get('cloudProvider', 'Unknown')}")
                
                if control.get('description'):
                    st.write(f"**Description:** {control.get('description')}")
                
                if control.get('remediation'):
                    st.write(f"**Remediation:** {control.get('remediation')}")

# Integration helper functions
def sync_wiz_to_database():
    """Sync Wiz data to local database"""
    try:
        from utils.database import get_database
        
        wiz = WizConnector()
        if not wiz.authenticate():
            return False
        
        db = get_database()
        
        # Sync security issues as alerts
        issues = wiz.get_issues(limit=50)
        for issue in issues:
            db.create_alert(
                title=issue.get('title', 'Wiz Security Issue'),
                description=issue.get('description', ''),
                severity=issue.get('severity', 'MEDIUM'),
                category='wiz_issue',
                source='wiz_platform',
                affected_assets=[issue.get('resource', {}).get('name', 'Unknown')],
                indicators={'wiz_issue_id': issue.get('id'), 'type': issue.get('type')},
                tags=['wiz', 'cloud_security']
            )
        
        # Sync vulnerabilities
        vulnerabilities = wiz.get_vulnerabilities(limit=30)
        for vuln in vulnerabilities:
            db.create_alert(
                title=f"Vulnerability: {vuln.get('name', 'Unknown CVE')}",
                description=vuln.get('description', ''),
                severity=vuln.get('severity', 'MEDIUM'),
                category='vulnerability',
                source='wiz_platform',
                indicators={
                    'cve_id': vuln.get('cveId'),
                    'cvss_score': vuln.get('cvssScore'),
                    'vendor': vuln.get('vendor')
                },
                tags=['wiz', 'vulnerability', 'cve']
            )
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to sync Wiz data: {str(e)}")
        return False