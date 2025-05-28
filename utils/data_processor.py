"""
Data processing utilities for cybersecurity platform
Handles data cleaning, transformation, and preprocessing for security analytics
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityDataProcessor:
    """Main class for processing security-related data"""
    
    def __init__(self):
        self.supported_log_formats = ['syslog', 'json', 'csv', 'windows_event']
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b')
        self.hash_patterns = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }
    
    def normalize_timestamps(self, data: pd.DataFrame, timestamp_column: str = 'timestamp') -> pd.DataFrame:
        """
        Normalize timestamps to a consistent format
        
        Args:
            data: DataFrame containing timestamp data
            timestamp_column: Name of the timestamp column
            
        Returns:
            DataFrame with normalized timestamps
        """
        try:
            if timestamp_column in data.columns:
                # Convert to datetime if not already
                data[timestamp_column] = pd.to_datetime(data[timestamp_column], errors='coerce')
                
                # Remove any invalid timestamps
                data = data.dropna(subset=[timestamp_column])
                
                # Add additional time-based features
                data['hour'] = data[timestamp_column].dt.hour
                data['day_of_week'] = data[timestamp_column].dt.dayofweek
                data['is_weekend'] = data['day_of_week'].isin([5, 6])
                data['is_business_hours'] = data['hour'].between(9, 17)
                
                logger.info(f"Normalized {len(data)} timestamps")
            
            return data
            
        except Exception as e:
            logger.error(f"Error normalizing timestamps: {str(e)}")
            return data
    
    def extract_network_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract network-related features from raw data
        
        Args:
            data: DataFrame containing network data
            
        Returns:
            DataFrame with extracted network features
        """
        try:
            # Extract IP addresses
            if 'raw_log' in data.columns:
                data['source_ips'] = data['raw_log'].str.findall(self.ip_pattern)
                data['ip_count'] = data['source_ips'].apply(len)
            
            # Calculate data transfer rates
            if all(col in data.columns for col in ['bytes_sent', 'bytes_received', 'duration']):
                data['total_bytes'] = data['bytes_sent'] + data['bytes_received']
                data['transfer_rate'] = data['total_bytes'] / data['duration'].replace(0, 1)
            
            # Protocol normalization
            if 'protocol' in data.columns:
                data['protocol'] = data['protocol'].str.upper()
                data['is_encrypted'] = data['protocol'].isin(['HTTPS', 'TLS', 'SSH', 'SFTP'])
            
            # Port categorization
            if 'port' in data.columns:
                data['port_category'] = data['port'].apply(self._categorize_port)
            
            return data
            
        except Exception as e:
            logger.error(f"Error extracting network features: {str(e)}")
            return data
    
    def _categorize_port(self, port: int) -> str:
        """Categorize network ports"""
        if port < 1024:
            return 'well_known'
        elif port < 49152:
            return 'registered'
        else:
            return 'dynamic'
    
    def extract_security_indicators(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract security-related indicators from data
        
        Args:
            data: DataFrame containing security event data
            
        Returns:
            DataFrame with extracted security indicators
        """
        try:
            # Extract file hashes
            if 'raw_log' in data.columns:
                for hash_type, pattern in self.hash_patterns.items():
                    data[f'{hash_type}_hashes'] = data['raw_log'].str.findall(pattern)
                    data[f'{hash_type}_count'] = data[f'{hash_type}_hashes'].apply(len)
            
            # Failed login detection
            if 'event_type' in data.columns:
                data['is_failed_login'] = data['event_type'].str.contains(
                    'failed|failure|invalid|denied', case=False, na=False
                )
            
            # Privilege escalation indicators
            if 'command' in data.columns:
                escalation_keywords = ['sudo', 'runas', 'psexec', 'wmic', 'powershell']
                data['privilege_escalation_risk'] = data['command'].str.contains(
                    '|'.join(escalation_keywords), case=False, na=False
                )
            
            # File operation risk scoring
            if 'file_path' in data.columns:
                sensitive_paths = ['/etc/', 'C:\\Windows\\System32\\', '/usr/bin/', '/root/']
                data['accesses_sensitive_path'] = data['file_path'].str.contains(
                    '|'.join(re.escape(path) for path in sensitive_paths), case=False, na=False
                )
            
            return data
            
        except Exception as e:
            logger.error(f"Error extracting security indicators: {str(e)}")
            return data
    
    def calculate_risk_scores(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Calculate risk scores for security events
        
        Args:
            data: DataFrame containing security event features
            
        Returns:
            DataFrame with calculated risk scores
        """
        try:
            risk_score = pd.Series(0.0, index=data.index)
            
            # Time-based risk factors
            if 'is_business_hours' in data.columns:
                risk_score += (~data['is_business_hours']) * 2.0
            
            if 'is_weekend' in data.columns:
                risk_score += data['is_weekend'] * 1.5
            
            # Network-based risk factors
            if 'is_encrypted' in data.columns:
                risk_score += (~data['is_encrypted']) * 1.0
            
            if 'port_category' in data.columns:
                risk_score += (data['port_category'] == 'dynamic') * 1.5
            
            # Security indicator risk factors
            if 'is_failed_login' in data.columns:
                risk_score += data['is_failed_login'] * 3.0
            
            if 'privilege_escalation_risk' in data.columns:
                risk_score += data['privilege_escalation_risk'] * 4.0
            
            if 'accesses_sensitive_path' in data.columns:
                risk_score += data['accesses_sensitive_path'] * 3.0
            
            # Normalize risk scores to 0-10 scale
            if risk_score.max() > 0:
                risk_score = (risk_score / risk_score.max()) * 10
            
            data['risk_score'] = risk_score
            
            # Categorize risk levels
            data['risk_level'] = pd.cut(
                data['risk_score'],
                bins=[0, 2.5, 5.0, 7.5, 10.0],
                labels=['Low', 'Medium', 'High', 'Critical'],
                include_lowest=True
            )
            
            return data
            
        except Exception as e:
            logger.error(f"Error calculating risk scores: {str(e)}")
            data['risk_score'] = 0.0
            data['risk_level'] = 'Low'
            return data
    
    def aggregate_events_by_time(self, data: pd.DataFrame, 
                                time_window: str = '1H',
                                timestamp_column: str = 'timestamp') -> pd.DataFrame:
        """
        Aggregate security events by time windows
        
        Args:
            data: DataFrame containing timestamped events
            time_window: Time window for aggregation (e.g., '1H', '15min')
            timestamp_column: Name of timestamp column
            
        Returns:
            DataFrame with aggregated events
        """
        try:
            if timestamp_column not in data.columns:
                logger.warning(f"Timestamp column '{timestamp_column}' not found")
                return pd.DataFrame()
            
            # Set timestamp as index for resampling
            data_indexed = data.set_index(timestamp_column)
            
            # Aggregate by time window
            aggregated = data_indexed.resample(time_window).agg({
                'event_type': 'count',
                'risk_score': ['mean', 'max', 'sum'],
                'source_ip': 'nunique' if 'source_ip' in data.columns else lambda x: 0,
                'user': 'nunique' if 'user' in data.columns else lambda x: 0
            }).reset_index()
            
            # Flatten column names
            aggregated.columns = ['_'.join(col).strip() if col[1] else col[0] 
                                for col in aggregated.columns.values]
            
            return aggregated
            
        except Exception as e:
            logger.error(f"Error aggregating events: {str(e)}")
            return pd.DataFrame()
    
    def detect_data_anomalies(self, data: pd.DataFrame, 
                             numeric_columns: List[str] = None) -> Dict[str, Any]:
        """
        Detect anomalies in numeric data using statistical methods
        
        Args:
            data: DataFrame to analyze
            numeric_columns: List of numeric columns to analyze
            
        Returns:
            Dictionary containing anomaly detection results
        """
        try:
            if numeric_columns is None:
                numeric_columns = data.select_dtypes(include=[np.number]).columns.tolist()
            
            anomalies = {}
            
            for column in numeric_columns:
                if column in data.columns and not data[column].empty:
                    col_data = data[column].dropna()
                    
                    # Calculate IQR-based outliers
                    Q1 = col_data.quantile(0.25)
                    Q3 = col_data.quantile(0.75)
                    IQR = Q3 - Q1
                    
                    lower_bound = Q1 - 1.5 * IQR
                    upper_bound = Q3 + 1.5 * IQR
                    
                    outliers = col_data[(col_data < lower_bound) | (col_data > upper_bound)]
                    
                    anomalies[column] = {
                        'outlier_count': len(outliers),
                        'outlier_percentage': (len(outliers) / len(col_data)) * 100,
                        'lower_bound': lower_bound,
                        'upper_bound': upper_bound,
                        'outlier_values': outliers.tolist()[:10]  # First 10 outliers
                    }
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return {}
    
    def clean_and_validate_data(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Clean and validate security data
        
        Args:
            data: Raw DataFrame to clean
            
        Returns:
            Tuple of (cleaned_data, validation_report)
        """
        try:
            original_rows = len(data)
            validation_report = {
                'original_rows': original_rows,
                'issues_found': [],
                'data_quality_score': 100.0
            }
            
            # Remove duplicate rows
            data_cleaned = data.drop_duplicates()
            duplicates_removed = original_rows - len(data_cleaned)
            if duplicates_removed > 0:
                validation_report['issues_found'].append(f"Removed {duplicates_removed} duplicate rows")
                validation_report['data_quality_score'] -= (duplicates_removed / original_rows) * 20
            
            # Handle missing values
            missing_percentage = (data_cleaned.isnull().sum() / len(data_cleaned)) * 100
            critical_missing = missing_percentage[missing_percentage > 50]
            
            if not critical_missing.empty:
                validation_report['issues_found'].append(f"Columns with >50% missing data: {list(critical_missing.index)}")
                validation_report['data_quality_score'] -= len(critical_missing) * 10
            
            # Validate IP addresses
            if 'source_ip' in data_cleaned.columns:
                invalid_ips = ~data_cleaned['source_ip'].str.match(self.ip_pattern, na=False)
                invalid_count = invalid_ips.sum()
                if invalid_count > 0:
                    validation_report['issues_found'].append(f"Found {invalid_count} invalid IP addresses")
                    validation_report['data_quality_score'] -= (invalid_count / len(data_cleaned)) * 15
            
            # Validate timestamps
            if 'timestamp' in data_cleaned.columns:
                invalid_timestamps = pd.to_datetime(data_cleaned['timestamp'], errors='coerce').isnull()
                invalid_count = invalid_timestamps.sum()
                if invalid_count > 0:
                    validation_report['issues_found'].append(f"Found {invalid_count} invalid timestamps")
                    data_cleaned = data_cleaned[~invalid_timestamps]
                    validation_report['data_quality_score'] -= (invalid_count / original_rows) * 25
            
            validation_report['final_rows'] = len(data_cleaned)
            validation_report['rows_removed'] = original_rows - len(data_cleaned)
            
            return data_cleaned, validation_report
            
        except Exception as e:
            logger.error(f"Error cleaning data: {str(e)}")
            return data, {'error': str(e)}

def process_log_file(file_path: str, log_format: str = 'auto') -> pd.DataFrame:
    """
    Process a log file and extract security-relevant information
    
    Args:
        file_path: Path to the log file
        log_format: Format of the log file ('auto', 'syslog', 'json', 'csv')
        
    Returns:
        DataFrame containing processed log data
    """
    try:
        processor = SecurityDataProcessor()
        
        # Auto-detect format if needed
        if log_format == 'auto':
            log_format = _detect_log_format(file_path)
        
        # Read file based on format
        if log_format == 'csv':
            data = pd.read_csv(file_path)
        elif log_format == 'json':
            data = pd.read_json(file_path, lines=True)
        else:
            # For syslog and other text formats
            with open(file_path, 'r') as f:
                lines = f.readlines()
            data = pd.DataFrame({'raw_log': lines})
        
        # Apply processing pipeline
        data = processor.normalize_timestamps(data)
        data = processor.extract_network_features(data)
        data = processor.extract_security_indicators(data)
        data = processor.calculate_risk_scores(data)
        
        # Clean and validate
        data, validation_report = processor.clean_and_validate_data(data)
        
        logger.info(f"Processed {len(data)} log entries from {file_path}")
        logger.info(f"Data quality score: {validation_report.get('data_quality_score', 'N/A')}")
        
        return data
        
    except Exception as e:
        logger.error(f"Error processing log file {file_path}: {str(e)}")
        return pd.DataFrame()

def _detect_log_format(file_path: str) -> str:
    """Detect log file format based on file extension and content"""
    try:
        if file_path.endswith('.csv'):
            return 'csv'
        elif file_path.endswith('.json') or file_path.endswith('.jsonl'):
            return 'json'
        else:
            # Try to detect JSON lines format
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                if first_line.startswith('{') and first_line.endswith('}'):
                    return 'json'
            return 'syslog'
    except Exception:
        return 'syslog'

def calculate_baseline_metrics(data: pd.DataFrame, 
                              time_column: str = 'timestamp',
                              metric_columns: List[str] = None) -> Dict[str, Dict[str, float]]:
    """
    Calculate baseline metrics for normal behavior detection
    
    Args:
        data: Historical data for baseline calculation
        time_column: Name of timestamp column
        metric_columns: List of metric columns to analyze
        
    Returns:
        Dictionary containing baseline statistics
    """
    try:
        if metric_columns is None:
            metric_columns = data.select_dtypes(include=[np.number]).columns.tolist()
        
        baselines = {}
        
        for column in metric_columns:
            if column in data.columns and not data[column].empty:
                col_data = data[column].dropna()
                
                baselines[column] = {
                    'mean': float(col_data.mean()),
                    'std': float(col_data.std()),
                    'median': float(col_data.median()),
                    'q25': float(col_data.quantile(0.25)),
                    'q75': float(col_data.quantile(0.75)),
                    'min': float(col_data.min()),
                    'max': float(col_data.max()),
                    'count': int(len(col_data))
                }
        
        return baselines
        
    except Exception as e:
        logger.error(f"Error calculating baseline metrics: {str(e)}")
        return {}

def export_processed_data(data: pd.DataFrame, 
                         output_path: str, 
                         format: str = 'csv') -> bool:
    """
    Export processed data to specified format
    
    Args:
        data: DataFrame to export
        output_path: Path for output file
        format: Export format ('csv', 'json', 'parquet')
        
    Returns:
        Boolean indicating success
    """
    try:
        if format == 'csv':
            data.to_csv(output_path, index=False)
        elif format == 'json':
            data.to_json(output_path, orient='records', lines=True)
        elif format == 'parquet':
            data.to_parquet(output_path, index=False)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        logger.info(f"Exported {len(data)} rows to {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error exporting data: {str(e)}")
        return False
