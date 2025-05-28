"""
Database management for CyberShield AI Platform
Handles PostgreSQL database operations for security data storage
"""

import os
import logging
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import psycopg2
from psycopg2.extras import RealDictCursor
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityDatabase:
    """Main database class for security data management"""
    
    def __init__(self):
        self.connection = None
        self.connect()
        self.initialize_schema()
    
    def connect(self):
        """Establish database connection"""
        try:
            database_url = os.getenv('DATABASE_URL')
            if not database_url:
                raise ValueError("DATABASE_URL environment variable not found")
            
            self.connection = psycopg2.connect(database_url)
            logger.info("Successfully connected to PostgreSQL database")
            
        except Exception as e:
            logger.error(f"Database connection failed: {str(e)}")
            raise
    
    def initialize_schema(self):
        """Create database tables if they don't exist"""
        try:
            with self.connection.cursor() as cursor:
                # Security Alerts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_alerts (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        title VARCHAR(255) NOT NULL,
                        description TEXT,
                        severity VARCHAR(20) NOT NULL,
                        category VARCHAR(50) NOT NULL,
                        source VARCHAR(100) NOT NULL,
                        affected_assets TEXT[],
                        indicators JSONB,
                        status VARCHAR(20) DEFAULT 'new',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        acknowledged_by VARCHAR(100),
                        acknowledged_at TIMESTAMP,
                        resolved_at TIMESTAMP,
                        escalated BOOLEAN DEFAULT FALSE,
                        escalation_level INTEGER DEFAULT 0,
                        tags TEXT[]
                    )
                """)
                
                # Security Incidents table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_incidents (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        title VARCHAR(255) NOT NULL,
                        incident_type VARCHAR(100) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        status VARCHAR(20) DEFAULT 'new',
                        assigned_to VARCHAR(100),
                        affected_systems TEXT[],
                        description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        response_time_minutes INTEGER,
                        resolution_eta_hours INTEGER,
                        priority_score INTEGER,
                        resolved_at TIMESTAMP
                    )
                """)
                
                # Threat Intelligence table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_intelligence (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        ioc_value VARCHAR(500) NOT NULL,
                        ioc_type VARCHAR(50) NOT NULL,
                        threat_type VARCHAR(100),
                        confidence INTEGER,
                        source VARCHAR(100),
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        tags TEXT[],
                        is_active BOOLEAN DEFAULT TRUE,
                        UNIQUE(ioc_value, ioc_type)
                    )
                """)
                
                # Network Events table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS network_events (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        source_ip INET,
                        destination_ip INET,
                        source_port INTEGER,
                        destination_port INTEGER,
                        protocol VARCHAR(10),
                        bytes_transferred BIGINT,
                        connection_count INTEGER,
                        risk_level VARCHAR(20),
                        geolocation VARCHAR(100),
                        threat_indicators TEXT[],
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_suspicious BOOLEAN DEFAULT FALSE
                    )
                """)
                
                # User Activities table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_activities (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        username VARCHAR(100) NOT NULL,
                        department VARCHAR(100),
                        activity_type VARCHAR(100),
                        source_ip INET,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        risk_score FLOAT,
                        is_business_hours BOOLEAN,
                        is_weekend BOOLEAN,
                        file_path TEXT,
                        command TEXT,
                        success BOOLEAN,
                        anomaly_score FLOAT
                    )
                """)
                
                # Anomaly Detection Results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS anomaly_detections (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        anomaly_type VARCHAR(100) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        source VARCHAR(100),
                        anomaly_score FLOAT,
                        baseline_value FLOAT,
                        observed_value FLOAT,
                        deviation_percentage FLOAT,
                        description TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_false_positive BOOLEAN DEFAULT FALSE
                    )
                """)
                
                # System Metrics table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS system_metrics (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        metric_name VARCHAR(100) NOT NULL,
                        metric_value FLOAT,
                        metric_unit VARCHAR(20),
                        source_system VARCHAR(100),
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        tags JSONB
                    )
                """)
                
                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON security_alerts(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON security_incidents(created_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_events(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_activities_timestamp ON user_activities(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_activities_username ON user_activities(username)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_intel_ioc ON threat_intelligence(ioc_value)")
                
                self.connection.commit()
                logger.info("Database schema initialized successfully")
                
        except Exception as e:
            logger.error(f"Schema initialization failed: {str(e)}")
            self.connection.rollback()
            raise
    
    def create_alert(self, title: str, description: str, severity: str, 
                    category: str, source: str, affected_assets: List[str] = None,
                    indicators: Dict[str, Any] = None, tags: List[str] = None) -> str:
        """Create a new security alert"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO security_alerts 
                    (title, description, severity, category, source, affected_assets, indicators, tags)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (title, description, severity, category, source, 
                     affected_assets or [], json.dumps(indicators or {}), tags or []))
                
                alert_id = cursor.fetchone()[0]
                self.connection.commit()
                logger.info(f"Created alert {alert_id}")
                return str(alert_id)
                
        except Exception as e:
            logger.error(f"Failed to create alert: {str(e)}")
            self.connection.rollback()
            return ""
    
    def get_recent_alerts(self, hours: int = 24, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent security alerts"""
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM security_alerts 
                    WHERE created_at >= %s 
                    ORDER BY created_at DESC 
                    LIMIT %s
                """, (datetime.now() - timedelta(hours=hours), limit))
                
                alerts = [dict(row) for row in cursor.fetchall()]
                return alerts
                
        except Exception as e:
            logger.error(f"Failed to get recent alerts: {str(e)}")
            return []
    
    def create_incident(self, title: str, incident_type: str, severity: str,
                       affected_systems: List[str], assigned_to: str = None,
                       description: str = None) -> str:
        """Create a new security incident"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO security_incidents 
                    (title, incident_type, severity, affected_systems, assigned_to, description)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (title, incident_type, severity, affected_systems, assigned_to, description))
                
                incident_id = cursor.fetchone()[0]
                self.connection.commit()
                logger.info(f"Created incident {incident_id}")
                return str(incident_id)
                
        except Exception as e:
            logger.error(f"Failed to create incident: {str(e)}")
            self.connection.rollback()
            return ""
    
    def add_threat_ioc(self, ioc_value: str, ioc_type: str, threat_type: str,
                      confidence: int, source: str, tags: List[str] = None) -> bool:
        """Add threat intelligence IOC"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO threat_intelligence 
                    (ioc_value, ioc_type, threat_type, confidence, source, tags)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (ioc_value, ioc_type) 
                    DO UPDATE SET 
                        last_seen = CURRENT_TIMESTAMP,
                        confidence = EXCLUDED.confidence,
                        is_active = TRUE
                """, (ioc_value, ioc_type, threat_type, confidence, source, tags or []))
                
                self.connection.commit()
                logger.info(f"Added/updated IOC: {ioc_value}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to add IOC: {str(e)}")
            self.connection.rollback()
            return False
    
    def log_network_event(self, source_ip: str, dest_ip: str, source_port: int,
                         dest_port: int, protocol: str, bytes_transferred: int,
                         risk_level: str = "LOW", is_suspicious: bool = False) -> bool:
        """Log network event"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO network_events 
                    (source_ip, destination_ip, source_port, destination_port, 
                     protocol, bytes_transferred, risk_level, is_suspicious)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (source_ip, dest_ip, source_port, dest_port, protocol, 
                     bytes_transferred, risk_level, is_suspicious))
                
                self.connection.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to log network event: {str(e)}")
            self.connection.rollback()
            return False
    
    def log_user_activity(self, username: str, activity_type: str, source_ip: str = None,
                         risk_score: float = 0.0, success: bool = True,
                         file_path: str = None, command: str = None) -> bool:
        """Log user activity"""
        try:
            with self.connection.cursor() as cursor:
                now = datetime.now()
                is_business_hours = 9 <= now.hour <= 17
                is_weekend = now.weekday() >= 5
                
                cursor.execute("""
                    INSERT INTO user_activities 
                    (username, activity_type, source_ip, risk_score, 
                     is_business_hours, is_weekend, file_path, command, success)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (username, activity_type, source_ip, risk_score, 
                     is_business_hours, is_weekend, file_path, command, success))
                
                self.connection.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to log user activity: {str(e)}")
            self.connection.rollback()
            return False
    
    def record_anomaly(self, anomaly_type: str, severity: str, source: str,
                      anomaly_score: float, baseline_value: float = None,
                      observed_value: float = None, description: str = None) -> bool:
        """Record anomaly detection result"""
        try:
            with self.connection.cursor() as cursor:
                deviation_pct = None
                if baseline_value and observed_value:
                    deviation_pct = ((observed_value - baseline_value) / baseline_value) * 100
                
                cursor.execute("""
                    INSERT INTO anomaly_detections 
                    (anomaly_type, severity, source, anomaly_score, 
                     baseline_value, observed_value, deviation_percentage, description)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (anomaly_type, severity, source, anomaly_score,
                     baseline_value, observed_value, deviation_pct, description))
                
                self.connection.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to record anomaly: {str(e)}")
            self.connection.rollback()
            return False
    
    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get metrics for dashboard"""
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Alert statistics
                cursor.execute("""
                    SELECT 
                        severity,
                        COUNT(*) as count
                    FROM security_alerts 
                    WHERE created_at >= %s 
                    GROUP BY severity
                """, (datetime.now() - timedelta(days=1),))
                alert_stats = {row['severity']: row['count'] for row in cursor.fetchall()}
                
                # Incident statistics
                cursor.execute("""
                    SELECT 
                        status,
                        COUNT(*) as count
                    FROM security_incidents 
                    WHERE created_at >= %s 
                    GROUP BY status
                """, (datetime.now() - timedelta(days=7),))
                incident_stats = {row['status']: row['count'] for row in cursor.fetchall()}
                
                # Network activity
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_connections,
                        COUNT(*) FILTER (WHERE is_suspicious = TRUE) as suspicious_connections
                    FROM network_events 
                    WHERE timestamp >= %s
                """, (datetime.now() - timedelta(hours=24),))
                network_stats = cursor.fetchone()
                
                # Anomaly count
                cursor.execute("""
                    SELECT COUNT(*) as anomaly_count
                    FROM anomaly_detections 
                    WHERE timestamp >= %s
                """, (datetime.now() - timedelta(days=1),))
                anomaly_count = cursor.fetchone()['anomaly_count']
                
                return {
                    'alert_stats': alert_stats,
                    'incident_stats': incident_stats,
                    'network_stats': dict(network_stats),
                    'anomaly_count': anomaly_count
                }
                
        except Exception as e:
            logger.error(f"Failed to get dashboard metrics: {str(e)}")
            return {}
    
    def get_threat_timeline(self, days: int = 7) -> pd.DataFrame:
        """Get threat detection timeline data"""
        try:
            query = """
                SELECT 
                    DATE_TRUNC('hour', created_at) as time_bucket,
                    severity,
                    COUNT(*) as threat_count
                FROM security_alerts 
                WHERE created_at >= %s 
                GROUP BY time_bucket, severity
                ORDER BY time_bucket
            """
            
            return pd.read_sql_query(query, self.connection, 
                                   params=(datetime.now() - timedelta(days=days),))
            
        except Exception as e:
            logger.error(f"Failed to get threat timeline: {str(e)}")
            return pd.DataFrame()
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")

# Global database instance
db = None

def get_database() -> SecurityDatabase:
    """Get database instance"""
    global db
    if db is None:
        db = SecurityDatabase()
    return db

def initialize_sample_data():
    """Initialize sample security data"""
    try:
        database = get_database()
        
        # Sample alerts
        sample_alerts = [
            {
                'title': 'Malware Detection - Suspicious Process',
                'description': 'Detected suspicious process execution with malware characteristics',
                'severity': 'HIGH',
                'category': 'malware',
                'source': 'endpoint_detection',
                'affected_assets': ['WORKSTATION-001'],
                'indicators': {'process_name': 'suspicious.exe', 'hash': 'abc123def456'},
                'tags': ['malware', 'endpoint']
            },
            {
                'title': 'Failed Login Attempts',
                'description': 'Multiple failed login attempts detected from external IP',
                'severity': 'MEDIUM',
                'category': 'authentication',
                'source': 'auth_monitor',
                'affected_assets': ['LOGIN-SERVER'],
                'indicators': {'source_ip': '192.168.1.100', 'attempts': 15},
                'tags': ['brute_force', 'authentication']
            },
            {
                'title': 'Data Exfiltration Attempt',
                'description': 'Large data transfer to external destination detected',
                'severity': 'CRITICAL',
                'category': 'data_breach',
                'source': 'network_monitor',
                'affected_assets': ['FILE-SERVER-01'],
                'indicators': {'dest_ip': '10.0.0.50', 'bytes': 1048576000},
                'tags': ['data_exfiltration', 'network']
            }
        ]
        
        for alert in sample_alerts:
            database.create_alert(**alert)
        
        # Sample incidents
        sample_incidents = [
            {
                'title': 'Ransomware Attack Response',
                'incident_type': 'Malware',
                'severity': 'CRITICAL',
                'affected_systems': ['FILE-SERVER-01', 'WORKSTATION-001', 'WORKSTATION-002'],
                'assigned_to': 'SOC Team',
                'description': 'Active ransomware infection detected on multiple systems'
            },
            {
                'title': 'Unauthorized Access Investigation',
                'incident_type': 'Unauthorized Access',
                'severity': 'HIGH',
                'affected_systems': ['DATABASE-SERVER'],
                'assigned_to': 'Security Analyst',
                'description': 'Suspicious access patterns detected on production database'
            }
        ]
        
        for incident in sample_incidents:
            database.create_incident(**incident)
        
        # Sample IOCs
        sample_iocs = [
            {'ioc_value': '192.168.1.100', 'ioc_type': 'IP Address', 'threat_type': 'C2', 'confidence': 85, 'source': 'threat_feed'},
            {'ioc_value': 'malicious-domain.com', 'ioc_type': 'Domain', 'threat_type': 'Phishing', 'confidence': 90, 'source': 'manual_analysis'},
            {'ioc_value': 'abc123def456789', 'ioc_type': 'File Hash', 'threat_type': 'Malware', 'confidence': 95, 'source': 'sandbox_analysis'}
        ]
        
        for ioc in sample_iocs:
            database.add_threat_ioc(**ioc)
        
        logger.info("Sample security data initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize sample data: {str(e)}")
        return False