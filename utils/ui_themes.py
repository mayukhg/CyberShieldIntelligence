"""
Adaptive UI Color Scheme Module
Dynamic theme system that adapts based on security threat levels
"""

import streamlit as st
from typing import Dict, Tuple, Any
from datetime import datetime
import random

class AdaptiveThemeManager:
    """Manages adaptive UI themes based on threat levels"""
    
    def __init__(self):
        self.current_threat_level = self.calculate_threat_level()
        self.theme_colors = self._initialize_theme_colors()
    
    def _initialize_theme_colors(self) -> Dict[str, Dict[str, str]]:
        """Initialize color schemes for different threat levels"""
        return {
            "LOW": {
                "primary": "#28a745",      # Green
                "secondary": "#6f42c1",    # Purple
                "success": "#28a745",      # Green
                "info": "#17a2b8",         # Cyan
                "warning": "#ffc107",      # Yellow
                "danger": "#dc3545",       # Red
                "light": "#f8f9fa",        # Light gray
                "dark": "#343a40",         # Dark gray
                "background": "#ffffff",   # White
                "sidebar": "#f0f8f0",      # Light green tint
                "card": "#f8fff8",         # Very light green
                "text": "#212529",         # Dark text
                "accent": "#20c997"        # Teal
            },
            "MODERATE": {
                "primary": "#fd7e14",      # Orange
                "secondary": "#6c757d",    # Gray
                "success": "#28a745",      # Green
                "info": "#17a2b8",         # Cyan
                "warning": "#ffc107",      # Yellow
                "danger": "#dc3545",       # Red
                "light": "#f8f9fa",        # Light gray
                "dark": "#343a40",         # Dark gray
                "background": "#fffbf7",   # Warm white
                "sidebar": "#fff4e6",      # Light orange tint
                "card": "#fff8f0",         # Very light orange
                "text": "#212529",         # Dark text
                "accent": "#fd7e14"        # Orange accent
            },
            "HIGH": {
                "primary": "#dc3545",      # Red
                "secondary": "#6c757d",    # Gray
                "success": "#28a745",      # Green
                "info": "#17a2b8",         # Cyan
                "warning": "#ffc107",      # Yellow
                "danger": "#dc3545",       # Red
                "light": "#f8f9fa",        # Light gray
                "dark": "#343a40",         # Dark gray
                "background": "#fff5f5",   # Light red tint
                "sidebar": "#ffe6e6",      # Light red
                "card": "#fff0f0",         # Very light red
                "text": "#212529",         # Dark text
                "accent": "#e74c3c"        # Bright red accent
            },
            "CRITICAL": {
                "primary": "#8b0000",      # Dark red
                "secondary": "#343a40",    # Dark gray
                "success": "#28a745",      # Green
                "info": "#17a2b8",         # Cyan
                "warning": "#ffc107",      # Yellow
                "danger": "#8b0000",       # Dark red
                "light": "#f8f9fa",        # Light gray
                "dark": "#212529",         # Very dark gray
                "background": "#fff0f0",   # Light red
                "sidebar": "#ffe0e0",      # Pink tint
                "card": "#ffe8e8",         # Light pink
                "text": "#212529",         # Dark text
                "accent": "#dc143c"        # Crimson accent
            }
        }
    
    def calculate_threat_level(self) -> str:
        """Calculate current threat level based on security metrics"""
        # For demonstration, simulate threat level based on time to show dynamic color changes
        # In production, this would analyze real security data from your database
        hour = datetime.now().hour
        
        # Simulate different threat levels throughout the day for demo
        if hour >= 22 or hour <= 6:  # Night hours - higher threat simulation
            return random.choice(["HIGH", "CRITICAL"])
        elif hour >= 9 and hour <= 17:  # Business hours - moderate threats
            return random.choice(["LOW", "MODERATE"])
        else:  # Evening hours - mixed threat levels
            return random.choice(["MODERATE", "HIGH"])
    
    def calculate_real_threat_level(self) -> str:
        """Calculate threat level from actual security data when available"""
        # This method will be used when your database functions are ready
        # For now, returns a simulated level
        return self.calculate_threat_level()
    
    def get_current_theme(self) -> Dict[str, str]:
        """Get current theme colors based on threat level"""
        return self.theme_colors[self.current_threat_level]
    
    def apply_custom_css(self):
        """Apply custom CSS based on current threat level"""
        theme = self.get_current_theme()
        
        css = f"""
        <style>
        /* Main container styling */
        .main .block-container {{
            background-color: {theme['background']};
            padding-top: 2rem;
        }}
        
        /* Sidebar styling */
        .css-1d391kg {{
            background-color: {theme['sidebar']};
        }}
        
        /* Header styling */
        .css-18e3th9 {{
            background-color: {theme['primary']};
            color: white;
        }}
        
        /* Metric cards */
        .metric-card {{
            background-color: {theme['card']};
            border: 1px solid {theme['primary']};
            border-radius: 10px;
            padding: 1rem;
            margin: 0.5rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        /* Threat level indicator */
        .threat-indicator {{
            background-color: {theme['primary']};
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            text-align: center;
            margin: 1rem 0;
        }}
        
        /* Alert boxes */
        .alert-box {{
            background-color: {theme['card']};
            border-left: 4px solid {theme['primary']};
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 5px;
        }}
        
        /* Button styling */
        .stButton > button {{
            background-color: {theme['primary']};
            color: white;
            border: none;
            border-radius: 5px;
            padding: 0.5rem 1rem;
        }}
        
        .stButton > button:hover {{
            background-color: {theme['accent']};
        }}
        
        /* Tab styling */
        .stTabs [data-baseweb="tab-list"] {{
            background-color: {theme['light']};
        }}
        
        .stTabs [data-baseweb="tab"] {{
            background-color: {theme['card']};
        }}
        
        .stTabs [aria-selected="true"] {{
            background-color: {theme['primary']};
            color: white;
        }}
        
        /* Chart containers */
        .chart-container {{
            background-color: {theme['card']};
            border-radius: 10px;
            padding: 1rem;
            margin: 1rem 0;
        }}
        
        /* Status indicators */
        .status-green {{ color: {theme['success']}; }}
        .status-yellow {{ color: {theme['warning']}; }}
        .status-orange {{ color: {theme['primary']}; }}
        .status-red {{ color: {theme['danger']}; }}
        
        /* Animated pulse effect for critical threats */
        .critical-pulse {{
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
            100% {{ opacity: 1; }}
        }}
        
        /* Sidebar threat level display */
        .sidebar-threat-level {{
            background-color: {theme['primary']};
            color: white;
            padding: 0.5rem;
            border-radius: 5px;
            text-align: center;
            font-weight: bold;
            margin: 1rem 0;
        }}
        </style>
        """
        
        st.markdown(css, unsafe_allow_html=True)
    
    def show_threat_level_indicator(self):
        """Display current threat level with appropriate styling"""
        threat_icons = {
            "LOW": "🟢",
            "MODERATE": "🟡", 
            "HIGH": "🟠",
            "CRITICAL": "🔴"
        }
        
        pulse_class = "critical-pulse" if self.current_threat_level == "CRITICAL" else ""
        
        st.markdown(f"""
        <div class="threat-indicator {pulse_class}">
            {threat_icons[self.current_threat_level]} Threat Level: {self.current_threat_level}
        </div>
        """, unsafe_allow_html=True)
    
    def show_sidebar_threat_status(self):
        """Show threat status in sidebar"""
        st.sidebar.markdown(f"""
        <div class="sidebar-threat-level">
            Current Threat Level<br>
            <strong>{self.current_threat_level}</strong>
        </div>
        """, unsafe_allow_html=True)
    
    def create_themed_metric_card(self, title: str, value: str, delta: str = None, 
                                 delta_color: str = "normal") -> str:
        """Create a themed metric card"""
        theme = self.get_current_theme()
        
        delta_html = ""
        if delta:
            delta_class = f"status-{delta_color}" if delta_color != "normal" else ""
            delta_html = f'<div class="{delta_class}" style="font-size: 0.8rem;">{delta}</div>'
        
        return f"""
        <div class="metric-card">
            <h3 style="color: {theme['primary']}; margin: 0;">{title}</h3>
            <h2 style="margin: 0.5rem 0;">{value}</h2>
            {delta_html}
        </div>
        """
    
    def create_alert_box(self, message: str, alert_type: str = "info") -> str:
        """Create a themed alert box"""
        theme = self.get_current_theme()
        
        type_colors = {
            "info": theme['info'],
            "success": theme['success'],
            "warning": theme['warning'],
            "danger": theme['danger']
        }
        
        color = type_colors.get(alert_type, theme['info'])
        
        return f"""
        <div class="alert-box" style="border-left-color: {color};">
            {message}
        </div>
        """
    
    def get_plotly_theme(self) -> Dict[str, Any]:
        """Get Plotly theme configuration based on current threat level"""
        theme = self.get_current_theme()
        
        return {
            'layout': {
                'plot_bgcolor': theme['background'],
                'paper_bgcolor': theme['card'],
                'font': {'color': theme['text']},
                'colorway': [
                    theme['primary'], theme['accent'], theme['info'],
                    theme['success'], theme['warning'], theme['danger']
                ]
            }
        }
    
    def refresh_threat_level(self):
        """Refresh threat level calculation"""
        self.current_threat_level = self.calculate_threat_level()
        return self.current_threat_level
    
    def get_threat_level_description(self) -> str:
        """Get description of current threat level"""
        descriptions = {
            "LOW": "🟢 Security posture is good. Normal operations with minimal risk.",
            "MODERATE": "🟡 Some security concerns detected. Monitor closely and take preventive action.",
            "HIGH": "🟠 Elevated security risk. Immediate attention required for several issues.",
            "CRITICAL": "🔴 Critical security threats detected. Emergency response protocols activated."
        }
        return descriptions[self.current_threat_level]
    
    def get_recommended_actions(self) -> list:
        """Get recommended actions based on threat level"""
        actions = {
            "LOW": [
                "Continue regular security monitoring",
                "Review and update security policies",
                "Conduct routine security training",
                "Perform scheduled vulnerability scans"
            ],
            "MODERATE": [
                "Increase monitoring frequency",
                "Review recent security alerts",
                "Verify all security controls are active",
                "Check for pending security updates"
            ],
            "HIGH": [
                "Activate enhanced monitoring protocols",
                "Review and contain active threats",
                "Brief security team on current risks",
                "Implement additional security controls"
            ],
            "CRITICAL": [
                "Activate incident response team",
                "Isolate affected systems immediately",
                "Brief executive leadership",
                "Consider emergency security measures"
            ]
        }
        return actions[self.current_threat_level]

# Global theme manager instance
theme_manager = AdaptiveThemeManager()

def apply_adaptive_theme():
    """Apply adaptive theme to current page"""
    theme_manager.apply_custom_css()
    return theme_manager

def get_current_theme_colors():
    """Get current theme colors"""
    return theme_manager.get_current_theme()

def show_threat_status():
    """Show current threat status"""
    theme_manager.show_threat_level_indicator()
    return theme_manager.current_threat_level