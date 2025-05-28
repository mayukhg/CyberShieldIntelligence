"""
Security Configuration Module for CyberShield AI Platform

This module centralizes all security configurations and settings for the cybersecurity platform.
It provides a single source of truth for security policies, encryption settings, and access controls.

Security Configurations Implemented:
- Encryption standards and key management
- Access control policies and user permissions
- Session management and timeout settings
- API security configurations and rate limits
- Audit logging and compliance settings
- Password policies and authentication requirements
"""

import os                           # Environment variable access for secure configuration
from datetime import timedelta     # Time-based security settings
from typing import Dict, Any, List # Type hints for configuration validation

class SecurityConfig:
    """
    Centralized security configuration management for the CyberShield platform.
    
    This class defines all security-related settings including:
    - Authentication and authorization policies
    - Encryption standards and key management
    - Session security and timeout configurations
    - API rate limiting and abuse prevention
    - Audit logging and compliance requirements
    """
    
    # SECURITY: Authentication and session management settings
    SESSION_CONFIG = {
        'session_timeout': timedelta(hours=8),       # Auto-logout after 8 hours of inactivity
        'max_concurrent_sessions': 3,                # Limit simultaneous sessions per user
        'require_mfa': True,                         # Multi-factor authentication required
        'password_min_length': 12,                   # Minimum password length
        'password_complexity': True,                 # Require complex passwords
        'session_token_length': 32,                  # Secure session token length
        'remember_me_duration': timedelta(days=30)   # Remember me functionality duration
    }
    
    # SECURITY: Database security configurations
    DATABASE_CONFIG = {
        'ssl_mode': 'require',                       # Force SSL/TLS for database connections
        'connection_timeout': 10,                    # Prevent hanging database connections
        'query_timeout': 30000,                      # Maximum query execution time (ms)
        'max_connections': 20,                       # Database connection pool limit
        'enable_query_logging': True,                # Log all database queries for audit
        'encrypt_sensitive_fields': True,            # Encrypt PII and sensitive data
        'backup_encryption': True                    # Encrypt database backups
    }
    
    # SECURITY: API security and rate limiting
    API_CONFIG = {
        'rate_limits': {
            'general': {'requests': 1000, 'window': 3600},      # 1000 requests per hour
            'authentication': {'requests': 10, 'window': 900},   # 10 auth attempts per 15 min
            'ai_chat': {'requests': 50, 'window': 3600},         # 50 AI chat requests per hour
            'data_export': {'requests': 5, 'window': 3600}       # 5 data exports per hour
        },
        'require_api_key': True,                     # API key required for all endpoints
        'api_key_length': 64,                        # API key length for security
        'enable_cors': False,                        # Disable CORS for security
        'max_request_size': '10MB',                  # Limit request payload size
        'enable_request_signing': True               # Require request signatures
    }
    
    # SECURITY: Encryption and cryptographic settings
    ENCRYPTION_CONFIG = {
        'algorithm': 'AES-256-GCM',                  # Advanced encryption standard
        'key_derivation': 'PBKDF2',                  # Password-based key derivation
        'salt_length': 32,                           # Cryptographic salt length
        'iteration_count': 100000,                   # PBKDF2 iteration count
        'iv_length': 16,                             # Initialization vector length
        'tag_length': 16,                            # Authentication tag length
        'key_rotation_days': 90                      # Rotate encryption keys every 90 days
    }
    
    # SECURITY: Input validation and sanitization rules
    INPUT_VALIDATION = {
        'max_input_length': 10000,                   # Maximum input size
        'allowed_file_types': ['.pdf', '.txt', '.csv'],  # Allowed upload file types
        'max_file_size': '50MB',                     # Maximum file upload size
        'sanitize_html': True,                       # HTML sanitization enabled
        'block_scripts': True,                       # Block script execution
        'validate_sql': True,                        # SQL injection validation
        'check_xss': True                           # Cross-site scripting protection
    }
    
    # SECURITY: Audit logging and compliance settings
    AUDIT_CONFIG = {
        'log_all_access': True,                      # Log all system access attempts
        'log_data_changes': True,                    # Log all data modifications
        'log_failed_auth': True,                     # Log failed authentication attempts
        'log_admin_actions': True,                   # Log administrative actions
        'retention_days': 2555,                      # Keep logs for 7 years (compliance)
        'encrypt_logs': True,                        # Encrypt audit logs
        'log_format': 'json',                        # Structured logging format
        'include_ip_geolocation': True               # Track geographic access patterns
    }
    
    # SECURITY: Network security configurations
    NETWORK_CONFIG = {
        'enable_firewall': True,                     # Enable application firewall
        'block_tor_exit_nodes': True,                # Block known Tor exit nodes
        'enable_ddos_protection': True,              # DDoS attack protection
        'max_connections_per_ip': 100,               # Limit connections per IP address
        'enable_intrusion_detection': True,          # Network intrusion detection
        'block_malicious_ips': True,                 # Automatically block malicious IPs
        'geo_blocking_enabled': False                # Geographic blocking (configurable)
    }
    
    # SECURITY: Content Security Policy (CSP) headers
    CSP_CONFIG = {
        'default_src': "'self'",                     # Default source policy
        'script_src': "'self' 'unsafe-inline'",     # Script source policy
        'style_src': "'self' 'unsafe-inline'",      # Style source policy
        'img_src': "'self' data: https:",           # Image source policy
        'connect_src': "'self' https:",              # Connection source policy
        'font_src': "'self' https:",                # Font source policy
        'object_src': "'none'",                      # Object embedding policy
        'frame_ancestors': "'none'"                  # Frame embedding policy
    }
    
    @classmethod
    def get_config(cls, config_section: str) -> Dict[str, Any]:
        """
        Retrieve a specific security configuration section.
        
        Args:
            config_section: Name of the configuration section to retrieve
            
        Returns:
            Dict containing the requested configuration settings
        """
        config_map = {
            'session': cls.SESSION_CONFIG,
            'database': cls.DATABASE_CONFIG,
            'api': cls.API_CONFIG,
            'encryption': cls.ENCRYPTION_CONFIG,
            'input_validation': cls.INPUT_VALIDATION,
            'audit': cls.AUDIT_CONFIG,
            'network': cls.NETWORK_CONFIG,
            'csp': cls.CSP_CONFIG
        }
        
        return config_map.get(config_section, {})
    
    @classmethod
    def validate_environment(cls) -> List[str]:
        """
        Validate that all required security environment variables are configured.
        
        Returns:
            List of missing or invalid environment variables
        """
        required_vars = [
            'DATABASE_URL',          # Database connection string
            'OPENAI_API_KEY',        # OpenAI API for chatbot functionality
            'SECRET_KEY',            # Application secret key for encryption
            'SECURITY_SALT'          # Cryptographic salt for key derivation
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        return missing_vars
    
    @classmethod
    def is_production_environment(cls) -> bool:
        """
        Determine if the application is running in production environment.
        
        Returns:
            True if production environment, False otherwise
        """
        env = os.getenv('ENVIRONMENT', 'development').lower()
        return env in ['production', 'prod']
    
    @classmethod
    def get_security_headers(cls) -> Dict[str, str]:
        """
        Generate security headers for HTTP responses.
        
        Returns:
            Dictionary of security headers to apply
        """
        csp_policy = "; ".join([f"{key} {value}" for key, value in cls.CSP_CONFIG.items()])
        
        return {
            'X-Content-Type-Options': 'nosniff',           # Prevent MIME type sniffing
            'X-Frame-Options': 'DENY',                     # Prevent clickjacking
            'X-XSS-Protection': '1; mode=block',           # XSS protection
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',  # HTTPS enforcement
            'Content-Security-Policy': csp_policy,         # Content security policy
            'Referrer-Policy': 'strict-origin-when-cross-origin',  # Referrer policy
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'  # Permissions policy
        }

# SECURITY: Global security configuration instance
security_config = SecurityConfig()