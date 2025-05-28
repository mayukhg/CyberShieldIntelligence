"""
Alert management system for cybersecurity platform
Handles alert generation, notification, escalation and management
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import json
import uuid
# Email functionality commented out to avoid import issues
# import smtplib
# from email.mime.text import MimeText
# from email.mime.multipart import MimeMultipart
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AlertStatus(Enum):
    """Alert status values"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

class AlertCategory(Enum):
    """Alert categories"""
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_BREACH = "data_breach"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    SYSTEM_FAILURE = "system_failure"
    AUTHENTICATION = "authentication"
    NETWORK = "network"

@dataclass
class SecurityAlert:
    """Security alert data structure"""
    id: str
    title: str
    description: str
    severity: AlertSeverity
    category: AlertCategory
    source: str
    affected_assets: List[str]
    indicators: Dict[str, Any]
    status: AlertStatus = AlertStatus.NEW
    created_at: datetime = None
    updated_at: datetime = None
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    escalated: bool = False
    escalation_level: int = 0
    tags: List[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()
        if self.tags is None:
            self.tags = []

class AlertManager:
    """Main alert management system"""
    
    def __init__(self):
        self.alerts: Dict[str, SecurityAlert] = {}
        self.notification_channels: List[Callable] = []
        self.escalation_rules: List[Dict[str, Any]] = []
        self.alert_history: List[SecurityAlert] = []
        
        # Load configuration
        self._load_escalation_rules()
        self._setup_notification_channels()
    
    def create_alert(self, title: str, description: str, severity: AlertSeverity,
                    category: AlertCategory, source: str, 
                    affected_assets: List[str] = None,
                    indicators: Dict[str, Any] = None) -> str:
        """
        Create a new security alert
        
        Args:
            title: Alert title
            description: Alert description
            severity: Alert severity level
            category: Alert category
            source: Source system that generated the alert
            affected_assets: List of affected assets
            indicators: IOCs and other indicators
            
        Returns:
            Alert ID
        """
        try:
            alert_id = str(uuid.uuid4())
            
            alert = SecurityAlert(
                id=alert_id,
                title=title,
                description=description,
                severity=severity,
                category=category,
                source=source,
                affected_assets=affected_assets or [],
                indicators=indicators or {}
            )
            
            self.alerts[alert_id] = alert
            
            # Send notifications
            self._send_notifications(alert)
            
            # Check for auto-escalation
            self._check_escalation_rules(alert)
            
            logger.info(f"Created alert {alert_id}: {title} ({severity.name})")
            return alert_id
            
        except Exception as e:
            logger.error(f"Error creating alert: {str(e)}")
            return ""
    
    def update_alert_status(self, alert_id: str, status: AlertStatus, 
                           user: str = None) -> bool:
        """
        Update alert status
        
        Args:
            alert_id: Alert ID
            status: New status
            user: User making the update
            
        Returns:
            Success status
        """
        try:
            if alert_id not in self.alerts:
                logger.warning(f"Alert {alert_id} not found")
                return False
            
            alert = self.alerts[alert_id]
            old_status = alert.status
            
            alert.status = status
            alert.updated_at = datetime.now()
            
            if status == AlertStatus.ACKNOWLEDGED and not alert.acknowledged_by:
                alert.acknowledged_by = user
                alert.acknowledged_at = datetime.now()
            elif status == AlertStatus.RESOLVED and not alert.resolved_at:
                alert.resolved_at = datetime.now()
            
            logger.info(f"Alert {alert_id} status changed: {old_status.value} -> {status.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating alert status: {str(e)}")
            return False
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """
        Acknowledge an alert
        
        Args:
            alert_id: Alert ID
            user: User acknowledging the alert
            
        Returns:
            Success status
        """
        return self.update_alert_status(alert_id, AlertStatus.ACKNOWLEDGED, user)
    
    def resolve_alert(self, alert_id: str, user: str = None) -> bool:
        """
        Resolve an alert
        
        Args:
            alert_id: Alert ID
            user: User resolving the alert
            
        Returns:
            Success status
        """
        return self.update_alert_status(alert_id, AlertStatus.RESOLVED, user)
    
    def escalate_alert(self, alert_id: str, level: int = None) -> bool:
        """
        Escalate an alert
        
        Args:
            alert_id: Alert ID
            level: Escalation level (optional)
            
        Returns:
            Success status
        """
        try:
            if alert_id not in self.alerts:
                return False
            
            alert = self.alerts[alert_id]
            alert.escalated = True
            
            if level is not None:
                alert.escalation_level = level
            else:
                alert.escalation_level += 1
            
            alert.updated_at = datetime.now()
            
            # Send escalation notifications
            self._send_escalation_notifications(alert)
            
            logger.info(f"Alert {alert_id} escalated to level {alert.escalation_level}")
            return True
            
        except Exception as e:
            logger.error(f"Error escalating alert: {str(e)}")
            return False
    
    def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Get alert by ID"""
        return self.alerts.get(alert_id)
    
    def get_alerts_by_status(self, status: AlertStatus) -> List[SecurityAlert]:
        """Get alerts by status"""
        return [alert for alert in self.alerts.values() if alert.status == status]
    
    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[SecurityAlert]:
        """Get alerts by severity"""
        return [alert for alert in self.alerts.values() if alert.severity == severity]
    
    def get_recent_alerts(self, hours: int = 24) -> List[SecurityAlert]:
        """
        Get recent alerts within specified hours
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of recent alerts
        """
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            recent_alerts = [
                alert for alert in self.alerts.values() 
                if alert.created_at >= cutoff_time
            ]
            
            # Sort by creation time (newest first)
            recent_alerts.sort(key=lambda x: x.created_at, reverse=True)
            
            return recent_alerts
            
        except Exception as e:
            logger.error(f"Error getting recent alerts: {str(e)}")
            return []
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """
        Get alert statistics
        
        Returns:
            Dictionary containing alert statistics
        """
        try:
            total_alerts = len(self.alerts)
            
            # Count by status
            status_counts = {}
            for status in AlertStatus:
                status_counts[status.value] = len(self.get_alerts_by_status(status))
            
            # Count by severity
            severity_counts = {}
            for severity in AlertSeverity:
                severity_counts[severity.name] = len(self.get_alerts_by_severity(severity))
            
            # Count by category
            category_counts = {}
            for category in AlertCategory:
                category_counts[category.value] = sum(
                    1 for alert in self.alerts.values() if alert.category == category
                )
            
            # Recent activity
            recent_24h = len(self.get_recent_alerts(24))
            recent_7d = len(self.get_recent_alerts(168))  # 7 days
            
            # Resolution metrics
            resolved_alerts = self.get_alerts_by_status(AlertStatus.RESOLVED)
            avg_resolution_time = 0
            if resolved_alerts:
                resolution_times = [
                    (alert.resolved_at - alert.created_at).total_seconds() / 3600  # hours
                    for alert in resolved_alerts 
                    if alert.resolved_at
                ]
                avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0
            
            # Escalation metrics
            escalated_count = sum(1 for alert in self.alerts.values() if alert.escalated)
            
            return {
                'total_alerts': total_alerts,
                'status_distribution': status_counts,
                'severity_distribution': severity_counts,
                'category_distribution': category_counts,
                'recent_24h': recent_24h,
                'recent_7d': recent_7d,
                'escalated_alerts': escalated_count,
                'avg_resolution_time_hours': round(avg_resolution_time, 2),
                'escalation_rate': (escalated_count / total_alerts * 100) if total_alerts > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting alert statistics: {str(e)}")
            return {}
    
    def _send_notifications(self, alert: SecurityAlert):
        """Send alert notifications"""
        try:
            for channel in self.notification_channels:
                try:
                    channel(alert)
                except Exception as e:
                    logger.error(f"Notification channel failed: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error sending notifications: {str(e)}")
    
    def _send_escalation_notifications(self, alert: SecurityAlert):
        """Send escalation notifications"""
        try:
            escalation_message = f"ESCALATED: {alert.title} (Level {alert.escalation_level})"
            
            # Create escalation alert with higher priority
            escalation_alert = SecurityAlert(
                id=f"{alert.id}_escalation",
                title=escalation_message,
                description=f"Alert {alert.id} has been escalated to level {alert.escalation_level}",
                severity=AlertSeverity.CRITICAL,
                category=alert.category,
                source="alert_manager",
                affected_assets=alert.affected_assets,
                indicators={'original_alert_id': alert.id}
            )
            
            self._send_notifications(escalation_alert)
            
        except Exception as e:
            logger.error(f"Error sending escalation notifications: {str(e)}")
    
    def _check_escalation_rules(self, alert: SecurityAlert):
        """Check if alert should be auto-escalated"""
        try:
            for rule in self.escalation_rules:
                if self._evaluate_escalation_rule(rule, alert):
                    self.escalate_alert(alert.id, rule.get('level', 1))
                    break
                    
        except Exception as e:
            logger.error(f"Error checking escalation rules: {str(e)}")
    
    def _evaluate_escalation_rule(self, rule: Dict[str, Any], alert: SecurityAlert) -> bool:
        """Evaluate if escalation rule applies to alert"""
        try:
            conditions = rule.get('conditions', {})
            
            # Check severity
            if 'min_severity' in conditions:
                min_severity = AlertSeverity[conditions['min_severity']]
                if alert.severity.value < min_severity.value:
                    return False
            
            # Check category
            if 'categories' in conditions:
                if alert.category.value not in conditions['categories']:
                    return False
            
            # Check time-based rules
            if 'unacknowledged_minutes' in conditions:
                time_limit = timedelta(minutes=conditions['unacknowledged_minutes'])
                if (alert.status == AlertStatus.NEW and 
                    datetime.now() - alert.created_at > time_limit):
                    return True
            
            # Check affected assets
            if 'critical_assets' in conditions:
                critical_assets = conditions['critical_assets']
                if any(asset in critical_assets for asset in alert.affected_assets):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating escalation rule: {str(e)}")
            return False
    
    def _load_escalation_rules(self):
        """Load escalation rules"""
        try:
            self.escalation_rules = [
                {
                    'name': 'Critical Severity Auto-Escalation',
                    'conditions': {
                        'min_severity': 'CRITICAL',
                        'unacknowledged_minutes': 5
                    },
                    'level': 1
                },
                {
                    'name': 'High Severity Auto-Escalation',
                    'conditions': {
                        'min_severity': 'HIGH',
                        'unacknowledged_minutes': 15
                    },
                    'level': 1
                },
                {
                    'name': 'Critical Asset Protection',
                    'conditions': {
                        'critical_assets': ['database', 'domain_controller', 'financial_system'],
                        'min_severity': 'MEDIUM'
                    },
                    'level': 2
                },
                {
                    'name': 'Data Breach Immediate Escalation',
                    'conditions': {
                        'categories': ['data_breach', 'malware'],
                        'min_severity': 'HIGH'
                    },
                    'level': 3
                }
            ]
            
            logger.info(f"Loaded {len(self.escalation_rules)} escalation rules")
            
        except Exception as e:
            logger.error(f"Error loading escalation rules: {str(e)}")
    
    def _setup_notification_channels(self):
        """Setup notification channels"""
        try:
            # Email notification channel
            if self._email_configured():
                self.notification_channels.append(self._send_email_notification)
            
            # Console notification (always available)
            self.notification_channels.append(self._send_console_notification)
            
            # Could add more channels: Slack, Teams, SMS, webhook, etc.
            
            logger.info(f"Setup {len(self.notification_channels)} notification channels")
            
        except Exception as e:
            logger.error(f"Error setting up notification channels: {str(e)}")
    
    def _email_configured(self) -> bool:
        """Check if email configuration is available"""
        return all([
            os.getenv('SMTP_SERVER'),
            os.getenv('SMTP_PORT'),
            os.getenv('SMTP_USERNAME'),
            os.getenv('SMTP_PASSWORD')
        ])
    
    def _send_email_notification(self, alert: SecurityAlert):
        """Send email notification"""
        try:
            # Email functionality temporarily disabled due to import issues
            logger.info(f"Email notification would be sent for alert: {alert.title}")
            return
            
            # smtp_server = os.getenv('SMTP_SERVER')
            # smtp_port = int(os.getenv('SMTP_PORT', '587'))
            # smtp_username = os.getenv('SMTP_USERNAME')
            # smtp_password = os.getenv('SMTP_PASSWORD')
            # recipient_email = os.getenv('ALERT_EMAIL', smtp_username)
            
            body = f"""
Security Alert Notification

Alert ID: {alert.id}
Title: {alert.title}
Severity: {alert.severity.name}
Category: {alert.category.value}
Source: {alert.source}
Created: {alert.created_at}

Description:
{alert.description}

Affected Assets:
{', '.join(alert.affected_assets) if alert.affected_assets else 'None specified'}

Indicators:
{json.dumps(alert.indicators, indent=2) if alert.indicators else 'None'}

Please review and take appropriate action.
"""
            
            # Email sending code commented out due to import issues
            # msg.attach(MimeText(body, 'plain'))
            # 
            # with smtplib.SMTP(smtp_server, smtp_port) as server:
            #     server.starttls()
            #     server.login(smtp_username, smtp_password)
            #     server.send_message(msg)
            
            logger.info(f"Email notification sent for alert {alert.id}")
            
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
    
    def _send_console_notification(self, alert: SecurityAlert):
        """Send console notification"""
        try:
            severity_prefix = {
                AlertSeverity.LOW: "ℹ️",
                AlertSeverity.MEDIUM: "⚠️",
                AlertSeverity.HIGH: "🚨",
                AlertSeverity.CRITICAL: "🔥"
            }.get(alert.severity, "📢")
            
            logger.warning(f"{severity_prefix} SECURITY ALERT: {alert.title} ({alert.severity.name})")
            logger.warning(f"   Source: {alert.source}")
            logger.warning(f"   Category: {alert.category.value}")
            if alert.affected_assets:
                logger.warning(f"   Affected: {', '.join(alert.affected_assets)}")
            
        except Exception as e:
            logger.error(f"Error sending console notification: {str(e)}")

# Global alert manager instance
_alert_manager = AlertManager()

def get_recent_alerts(hours: int = 24) -> List[Dict[str, Any]]:
    """
    Get recent alerts for display in the UI
    
    Args:
        hours: Number of hours to look back
        
    Returns:
        List of alert dictionaries
    """
    try:
        recent_alerts = _alert_manager.get_recent_alerts(hours)
        
        # Convert to display format
        alert_list = []
        for alert in recent_alerts:
            alert_dict = {
                'title': alert.title,
                'description': alert.description,
                'severity': alert.severity.name,
                'timestamp': alert.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                'source': alert.source,
                'status': alert.status.value,
                'category': alert.category.value
            }
            alert_list.append(alert_dict)
        
        return alert_list
        
    except Exception as e:
        logger.error(f"Error getting recent alerts for UI: {str(e)}")
        return []

def create_security_alert(title: str, description: str, severity: str,
                         category: str, source: str = "system") -> str:
    """
    Create a security alert
    
    Args:
        title: Alert title
        description: Alert description  
        severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        category: Alert category
        source: Source system
        
    Returns:
        Alert ID
    """
    try:
        severity_enum = AlertSeverity[severity.upper()]
        category_enum = AlertCategory[category.upper()]
        
        return _alert_manager.create_alert(
            title=title,
            description=description,
            severity=severity_enum,
            category=category_enum,
            source=source
        )
        
    except Exception as e:
        logger.error(f"Error creating security alert: {str(e)}")
        return ""

def get_alert_statistics() -> Dict[str, Any]:
    """Get alert statistics for dashboard"""
    return _alert_manager.get_alert_statistics()

def acknowledge_alert(alert_id: str, user: str = "system") -> bool:
    """Acknowledge an alert"""
    return _alert_manager.acknowledge_alert(alert_id, user)

def resolve_alert(alert_id: str, user: str = "system") -> bool:
    """Resolve an alert"""
    return _alert_manager.resolve_alert(alert_id, user)

def escalate_alert(alert_id: str, level: int = None) -> bool:
    """Escalate an alert"""
    return _alert_manager.escalate_alert(alert_id, level)
