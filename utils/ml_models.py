"""
Machine learning models for cybersecurity threat detection and analysis
Implements various ML algorithms for anomaly detection, threat classification, and prediction
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
import logging
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDetectionModel:
    """Machine learning model for threat detection and classification"""
    
    def __init__(self, model_type: str = 'isolation_forest'):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.is_trained = False
        self.model_path = f"models/{model_type}_threat_model.joblib"
        
        # Ensure models directory exists
        os.makedirs("models", exist_ok=True)
        
        # Initialize model based on type
        if model_type == 'isolation_forest':
            self.model = IsolationForest(contamination=0.1, random_state=42)
        elif model_type == 'random_forest':
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        else:
            raise ValueError(f"Unsupported model type: {model_type}")
    
    def prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """
        Prepare features for machine learning model
        
        Args:
            data: Raw security data
            
        Returns:
            Prepared feature matrix
        """
        try:
            # Select relevant features for threat detection
            feature_columns = [
                'risk_score', 'is_business_hours', 'is_weekend',
                'ip_count', 'transfer_rate', 'is_encrypted',
                'is_failed_login', 'privilege_escalation_risk'
            ]
            
            # Filter to available columns
            available_features = [col for col in feature_columns if col in data.columns]
            
            if not available_features:
                logger.warning("No suitable features found for model training")
                return np.array([])
            
            # Extract features
            features = data[available_features].copy()
            
            # Handle missing values
            features = features.fillna(0)
            
            # Convert boolean columns to numeric
            bool_columns = features.select_dtypes(include=['bool']).columns
            features[bool_columns] = features[bool_columns].astype(int)
            
            # Store feature columns for later use
            self.feature_columns = available_features
            
            return features.values
            
        except Exception as e:
            logger.error(f"Error preparing features: {str(e)}")
            return np.array([])
    
    def train(self, data: pd.DataFrame, labels: Optional[pd.Series] = None) -> Dict[str, Any]:
        """
        Train the threat detection model
        
        Args:
            data: Training data
            labels: Optional labels for supervised learning
            
        Returns:
            Training results and metrics
        """
        try:
            # Prepare features
            X = self.prepare_features(data)
            
            if X.size == 0:
                return {'error': 'No features available for training'}
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            training_results = {}
            
            if self.model_type == 'isolation_forest':
                # Unsupervised training
                self.model.fit(X_scaled)
                
                # Predict anomalies on training data for evaluation
                predictions = self.model.predict(X_scaled)
                anomaly_score = self.model.decision_function(X_scaled)
                
                training_results = {
                    'model_type': 'unsupervised',
                    'anomaly_count': np.sum(predictions == -1),
                    'anomaly_percentage': (np.sum(predictions == -1) / len(predictions)) * 100,
                    'avg_anomaly_score': np.mean(anomaly_score),
                    'training_samples': len(X_scaled)
                }
                
            elif self.model_type == 'random_forest' and labels is not None:
                # Supervised training
                y = self.label_encoder.fit_transform(labels)
                X_train, X_test, y_train, y_test = train_test_split(
                    X_scaled, y, test_size=0.2, random_state=42, stratify=y
                )
                
                self.model.fit(X_train, y_train)
                
                # Evaluate on test set
                y_pred = self.model.predict(X_test)
                y_pred_proba = self.model.predict_proba(X_test)
                
                training_results = {
                    'model_type': 'supervised',
                    'accuracy': self.model.score(X_test, y_test),
                    'classification_report': classification_report(y_test, y_pred, output_dict=True),
                    'feature_importance': dict(zip(self.feature_columns, self.model.feature_importances_)),
                    'training_samples': len(X_train),
                    'test_samples': len(X_test)
                }
                
                # Calculate AUC if binary classification
                if len(np.unique(y)) == 2:
                    training_results['auc_score'] = roc_auc_score(y_test, y_pred_proba[:, 1])
            
            # Save model
            self.save_model()
            self.is_trained = True
            
            logger.info(f"Model training completed: {training_results}")
            return training_results
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            return {'error': str(e)}
    
    def predict(self, data: pd.DataFrame) -> Dict[str, Any]:
        """
        Make predictions on new data
        
        Args:
            data: Data to make predictions on
            
        Returns:
            Prediction results
        """
        try:
            if not self.is_trained and not self.load_model():
                return {'error': 'Model not trained and no saved model found'}
            
            # Prepare features
            X = self.prepare_features(data)
            
            if X.size == 0:
                return {'error': 'No features available for prediction'}
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            predictions = {}
            
            if self.model_type == 'isolation_forest':
                # Predict anomalies
                pred = self.model.predict(X_scaled)
                scores = self.model.decision_function(X_scaled)
                
                predictions = {
                    'anomalies': (pred == -1).tolist(),
                    'anomaly_scores': scores.tolist(),
                    'anomaly_count': np.sum(pred == -1),
                    'total_samples': len(pred)
                }
                
            elif self.model_type == 'random_forest':
                # Predict threat classes
                pred = self.model.predict(X_scaled)
                pred_proba = self.model.predict_proba(X_scaled)
                
                predictions = {
                    'predicted_classes': self.label_encoder.inverse_transform(pred).tolist(),
                    'class_probabilities': pred_proba.tolist(),
                    'max_probabilities': np.max(pred_proba, axis=1).tolist(),
                    'confidence_scores': np.max(pred_proba, axis=1).tolist()
                }
            
            return predictions
            
        except Exception as e:
            logger.error(f"Error making predictions: {str(e)}")
            return {'error': str(e)}
    
    def save_model(self) -> bool:
        """Save the trained model to disk"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'feature_columns': self.feature_columns,
                'model_type': self.model_type,
                'is_trained': self.is_trained
            }
            
            joblib.dump(model_data, self.model_path)
            logger.info(f"Model saved to {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            return False
    
    def load_model(self) -> bool:
        """Load a trained model from disk"""
        try:
            if not os.path.exists(self.model_path):
                logger.warning(f"No saved model found at {self.model_path}")
                return False
            
            model_data = joblib.load(self.model_path)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoder = model_data['label_encoder']
            self.feature_columns = model_data['feature_columns']
            self.model_type = model_data['model_type']
            self.is_trained = model_data['is_trained']
            
            logger.info(f"Model loaded from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False

class BehaviorAnalysisModel:
    """Model for analyzing user behavior patterns"""
    
    def __init__(self):
        self.clustering_model = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        self.behavior_baselines = {}
        self.is_trained = False
    
    def extract_behavior_features(self, data: pd.DataFrame, user_column: str = 'user') -> pd.DataFrame:
        """
        Extract behavioral features for each user
        
        Args:
            data: User activity data
            user_column: Column containing user identifiers
            
        Returns:
            DataFrame with user behavior features
        """
        try:
            # Group by user and calculate behavioral metrics
            user_features = data.groupby(user_column).agg({
                'timestamp': ['count', 'nunique'],  # Activity frequency and unique days
                'hour': lambda x: x.mode().iloc[0] if not x.empty else 12,  # Most common hour
                'is_weekend': 'mean',  # Weekend activity ratio
                'is_business_hours': 'mean',  # Business hours activity ratio
                'risk_score': ['mean', 'max', 'std'],  # Risk metrics
                'source_ip': 'nunique' if 'source_ip' in data.columns else lambda x: 0,  # IP diversity
                'file_path': 'nunique' if 'file_path' in data.columns else lambda x: 0  # File access diversity
            }).reset_index()
            
            # Flatten column names
            user_features.columns = ['_'.join(col).strip() if col[1] else col[0] 
                                   for col in user_features.columns.values]
            
            # Calculate additional behavioral metrics
            if 'timestamp_count' in user_features.columns:
                user_features['avg_daily_activity'] = user_features['timestamp_count'] / user_features['timestamp_nunique']
            
            return user_features
            
        except Exception as e:
            logger.error(f"Error extracting behavior features: {str(e)}")
            return pd.DataFrame()
    
    def detect_anomalous_users(self, data: pd.DataFrame) -> Dict[str, Any]:
        """
        Detect users with anomalous behavior patterns
        
        Args:
            data: User activity data
            
        Returns:
            Results of anomaly detection
        """
        try:
            # Extract user behavior features
            user_features = self.extract_behavior_features(data)
            
            if user_features.empty:
                return {'error': 'No user features extracted'}
            
            # Prepare features for clustering
            feature_columns = user_features.select_dtypes(include=[np.number]).columns
            X = user_features[feature_columns].fillna(0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Perform clustering to identify anomalous behavior
            clusters = self.clustering_model.fit_predict(X_scaled)
            
            # Users in cluster -1 are considered anomalous (noise points in DBSCAN)
            anomalous_users = user_features[clusters == -1]['user'].tolist()
            
            # Calculate behavior scores for all users
            behavior_scores = self._calculate_behavior_scores(user_features, feature_columns)
            
            results = {
                'anomalous_users': anomalous_users,
                'total_users': len(user_features),
                'anomaly_percentage': (len(anomalous_users) / len(user_features)) * 100,
                'user_behavior_scores': behavior_scores,
                'cluster_counts': dict(zip(*np.unique(clusters, return_counts=True)))
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error detecting anomalous users: {str(e)}")
            return {'error': str(e)}
    
    def _calculate_behavior_scores(self, user_features: pd.DataFrame, 
                                  feature_columns: List[str]) -> Dict[str, float]:
        """Calculate behavior risk scores for users"""
        try:
            scores = {}
            
            for _, user_row in user_features.iterrows():
                score = 0.0
                
                # Weekend activity penalty
                if 'is_weekend_mean' in user_row:
                    score += user_row['is_weekend_mean'] * 20
                
                # Off-hours activity penalty
                if 'is_business_hours_mean' in user_row:
                    score += (1 - user_row['is_business_hours_mean']) * 30
                
                # High risk activity penalty
                if 'risk_score_mean' in user_row:
                    score += user_row['risk_score_mean'] * 10
                
                # IP diversity penalty (possible account sharing)
                if 'source_ip_nunique' in user_row and user_row['source_ip_nunique'] > 5:
                    score += min(user_row['source_ip_nunique'] * 2, 20)
                
                # Normalize score to 0-100 scale
                score = min(score, 100)
                
                scores[user_row['user']] = score
            
            return scores
            
        except Exception as e:
            logger.error(f"Error calculating behavior scores: {str(e)}")
            return {}

class NetworkAnomalyDetector:
    """Specialized model for network traffic anomaly detection"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.traffic_baselines = {}
        self.is_trained = False
    
    def extract_network_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract network-specific features for anomaly detection
        
        Args:
            data: Network traffic data
            
        Returns:
            DataFrame with network features
        """
        try:
            # Time-based aggregation of network metrics
            time_features = data.groupby([
                data['timestamp'].dt.floor('H') if 'timestamp' in data.columns else pd.Grouper(freq='H')
            ]).agg({
                'bytes_sent': ['sum', 'mean', 'std'] if 'bytes_sent' in data.columns else lambda x: 0,
                'bytes_received': ['sum', 'mean', 'std'] if 'bytes_received' in data.columns else lambda x: 0,
                'packet_count': ['sum', 'mean'] if 'packet_count' in data.columns else lambda x: 0,
                'connection_count': 'sum' if 'connection_count' in data.columns else lambda x: 0,
                'unique_ips': 'nunique' if 'source_ip' in data.columns else lambda x: 0,
                'unique_ports': 'nunique' if 'port' in data.columns else lambda x: 0
            }).reset_index()
            
            # Flatten column names
            time_features.columns = ['_'.join(col).strip() if col[1] else col[0] 
                                   for col in time_features.columns.values]
            
            # Calculate derived features
            if 'bytes_sent_sum' in time_features.columns and 'bytes_received_sum' in time_features.columns:
                time_features['total_bytes'] = time_features['bytes_sent_sum'] + time_features['bytes_received_sum']
                time_features['bytes_ratio'] = time_features['bytes_sent_sum'] / (time_features['bytes_received_sum'] + 1)
            
            return time_features
            
        except Exception as e:
            logger.error(f"Error extracting network features: {str(e)}")
            return pd.DataFrame()
    
    def detect_network_anomalies(self, data: pd.DataFrame) -> Dict[str, Any]:
        """
        Detect anomalies in network traffic patterns
        
        Args:
            data: Network traffic data
            
        Returns:
            Network anomaly detection results
        """
        try:
            # Extract network features
            network_features = self.extract_network_features(data)
            
            if network_features.empty:
                return {'error': 'No network features extracted'}
            
            # Prepare features for anomaly detection
            feature_columns = network_features.select_dtypes(include=[np.number]).columns
            X = network_features[feature_columns].fillna(0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train isolation forest if not trained
            if not self.is_trained:
                self.isolation_forest.fit(X_scaled)
                self.is_trained = True
            
            # Detect anomalies
            predictions = self.isolation_forest.predict(X_scaled)
            anomaly_scores = self.isolation_forest.decision_function(X_scaled)
            
            # Identify anomalous time periods
            anomalous_indices = np.where(predictions == -1)[0]
            
            results = {
                'anomalous_periods': len(anomalous_indices),
                'total_periods': len(predictions),
                'anomaly_percentage': (len(anomalous_indices) / len(predictions)) * 100,
                'anomaly_scores': anomaly_scores.tolist(),
                'anomaly_timestamps': network_features.iloc[anomalous_indices]['timestamp'].tolist() if 'timestamp' in network_features.columns else [],
                'avg_anomaly_score': np.mean(anomaly_scores)
            }
            
            return results
            
        except Exception as e:
            logger.error(f"Error detecting network anomalies: {str(e)}")
            return {'error': str(e)}

def predict_threats() -> Dict[str, Any]:
    """
    Main function for threat prediction using ensemble of models
    
    Returns:
        Dictionary containing threat predictions and confidence scores
    """
    try:
        # This would normally use real data from your security systems
        # For now, we'll simulate threat prediction based on current trends
        
        current_time = datetime.now()
        
        # Simulate threat prediction logic
        base_threat_level = 5  # Baseline threat level
        
        # Time-based risk factors
        hour = current_time.hour
        if hour < 6 or hour > 22:  # Off hours
            base_threat_level += 1
        
        if current_time.weekday() >= 5:  # Weekend
            base_threat_level += 0.5
        
        # Simulate trending threats
        threat_trends = {
            'ransomware': np.random.uniform(0.1, 0.8),
            'phishing': np.random.uniform(0.2, 0.9),
            'apt_activity': np.random.uniform(0.05, 0.6),
            'ddos': np.random.uniform(0.1, 0.5),
            'malware': np.random.uniform(0.3, 0.7)
        }
        
        # Calculate next 24h predictions
        next_24h_threats = int(base_threat_level + sum(threat_trends.values()) * 10)
        
        # Determine trend
        if base_threat_level > 6:
            trend = "Increasing"
        elif base_threat_level < 4:
            trend = "Decreasing"
        else:
            trend = "Stable"
        
        # Calculate confidence based on data quality and model performance
        confidence = min(95, 70 + np.random.randint(0, 25))
        
        predictions = {
            'next_24h': next_24h_threats,
            'trend': trend,
            'confidence': confidence,
            'threat_breakdown': threat_trends,
            'risk_factors': {
                'time_based': hour < 6 or hour > 22,
                'weekend': current_time.weekday() >= 5,
                'threat_intelligence': max(threat_trends.values()) > 0.7
            },
            'recommended_actions': _get_threat_recommendations(base_threat_level, threat_trends)
        }
        
        logger.info(f"Threat prediction completed: {next_24h_threats} threats predicted for next 24h")
        return predictions
        
    except Exception as e:
        logger.error(f"Error in threat prediction: {str(e)}")
        return {
            'next_24h': 'N/A',
            'trend': 'Unknown',
            'confidence': 0,
            'error': str(e)
        }

def _get_threat_recommendations(threat_level: float, threat_trends: Dict[str, float]) -> List[str]:
    """Generate threat-based recommendations"""
    recommendations = []
    
    if threat_level > 7:
        recommendations.append("Increase monitoring frequency")
        recommendations.append("Review incident response procedures")
    
    if threat_trends.get('phishing', 0) > 0.7:
        recommendations.append("Send phishing awareness reminder to users")
    
    if threat_trends.get('ransomware', 0) > 0.6:
        recommendations.append("Verify backup integrity and accessibility")
    
    if threat_trends.get('apt_activity', 0) > 0.5:
        recommendations.append("Review privileged account access")
    
    if not recommendations:
        recommendations.append("Continue normal monitoring")
    
    return recommendations

def retrain_models_with_new_data(data: pd.DataFrame, model_types: List[str] = None) -> Dict[str, Any]:
    """
    Retrain models with new security data
    
    Args:
        data: New training data
        model_types: List of model types to retrain
        
    Returns:
        Retraining results
    """
    try:
        if model_types is None:
            model_types = ['isolation_forest', 'random_forest']
        
        results = {}
        
        for model_type in model_types:
            try:
                model = ThreatDetectionModel(model_type)
                
                # Prepare labels for supervised models
                labels = None
                if model_type == 'random_forest' and 'threat_type' in data.columns:
                    labels = data['threat_type']
                
                training_result = model.train(data, labels)
                results[model_type] = training_result
                
            except Exception as e:
                results[model_type] = {'error': str(e)}
        
        logger.info(f"Model retraining completed for {len(model_types)} models")
        return results
        
    except Exception as e:
        logger.error(f"Error retraining models: {str(e)}")
        return {'error': str(e)}
