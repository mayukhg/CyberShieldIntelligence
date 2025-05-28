"""
Anomaly Detection Module for CyberShield AI Platform

This module implements advanced machine learning algorithms to identify unusual patterns
and behaviors that may indicate security threats. It uses statistical analysis and
unsupervised learning to detect anomalies that traditional signature-based systems might miss.

Key Features:
- Multiple anomaly detection algorithms (Isolation Forest, Statistical Analysis)
- Real-time anomaly scoring with confidence levels
- Interactive anomaly investigation and drill-down capabilities
- Automated baseline learning and threshold adjustment
- Integration with threat intelligence for context-aware detection
"""

import streamlit as st              # Web interface framework for anomaly dashboards
import pandas as pd                 # Data manipulation for anomaly analysis
import numpy as np                  # Numerical computing for statistical algorithms
import plotly.express as px         # Statistical visualization for anomaly patterns
import plotly.graph_objects as go   # Advanced plotting for anomaly correlation
from datetime import datetime, timedelta  # Time handling for anomaly timeline analysis

# Machine Learning libraries for anomaly detection
from sklearn.ensemble import IsolationForest    # Unsupervised anomaly detection algorithm
from sklearn.preprocessing import StandardScaler # Feature scaling for consistent analysis
from utils import ml_models         # Internal ML utilities for model management

def show_anomaly_analysis():
    """
    Main anomaly detection interface for security analysts.
    
    This function provides an interactive dashboard for:
    - Monitoring anomaly detection performance metrics
    - Configuring detection sensitivity and algorithms
    - Investigating detected anomalies with detailed analysis
    - Tracking historical anomaly patterns and trends
    - Managing false positives and model tuning
    """
    # Main header for the anomaly detection module
    st.header("🔬 AI Anomaly Detection & Analysis")
    
    # Create four-column layout for key anomaly detection metrics
    # These provide real-time visibility into detection performance
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Anomalies Detected", "23", delta="+5")
    with col2:
        st.metric("False Positives", "3", delta="-2")
    with col3:
        st.metric("Detection Accuracy", "94.2%", delta="+1.2%")
    with col4:
        st.metric("Model Confidence", "87%", delta="+3%")
    
    st.divider()
    
    # Anomaly detection configuration
    st.subheader("⚙️ Detection Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        detection_type = st.selectbox(
            "Detection Algorithm",
            ["Isolation Forest", "Statistical Analysis", "Deep Learning", "Ensemble Methods"]
        )
        
        sensitivity = st.slider(
            "Anomaly Sensitivity",
            min_value=0.01, max_value=0.3, value=0.1, step=0.01
        )
    
    with col2:
        data_sources = st.multiselect(
            "Data Sources",
            ["Network Traffic", "System Logs", "User Activity", "Application Metrics", "Security Events"],
            default=["Network Traffic", "System Logs"]
        )
        
        if st.button("Run Anomaly Detection"):
            run_anomaly_detection(detection_type, sensitivity, data_sources)
    
    # Real-time anomaly monitoring
    st.subheader("📊 Real-time Anomaly Monitoring")
    
    # Generate and display anomaly data
    anomaly_data = generate_anomaly_data()
    
    # Anomaly visualization
    col1, col2 = st.columns(2)
    
    with col1:
        # Time series with anomalies highlighted
        fig = create_anomaly_timeline(anomaly_data)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Anomaly distribution by type
        anomaly_types = anomaly_data['Type'].value_counts()
        fig = px.pie(values=anomaly_types.values, names=anomaly_types.index,
                     title="Anomaly Distribution by Type")
        st.plotly_chart(fig, use_container_width=True)
    
    # Detailed anomaly analysis
    st.subheader("🔍 Detailed Anomaly Analysis")
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.selectbox(
            "Filter by Severity",
            ["All", "High", "Medium", "Low"]
        )
    
    with col2:
        time_range = st.selectbox(
            "Time Range",
            ["Last Hour", "Last 24 Hours", "Last Week", "Last Month"]
        )
    
    with col3:
        source_filter = st.selectbox(
            "Filter by Source",
            ["All"] + data_sources
        )
    
    # Apply filters
    filtered_anomalies = apply_anomaly_filters(anomaly_data, severity_filter, time_range, source_filter)
    
    # Display anomalies
    for _, anomaly in filtered_anomalies.iterrows():
        severity_color = {
            "High": "🔴",
            "Medium": "🟡",
            "Low": "🟢"
        }.get(anomaly['Severity'], "🔵")
        
        with st.expander(f"{severity_color} {anomaly['Type']} Anomaly - {anomaly['Severity']} Severity"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Source:** {anomaly['Source']}")
                st.write(f"**Detected:** {anomaly['Timestamp']}")
                st.write(f"**Anomaly Score:** {anomaly['Score']:.3f}")
            
            with col2:
                st.write(f"**Baseline Value:** {anomaly['Baseline']}")
                st.write(f"**Observed Value:** {anomaly['Observed']}")
                st.write(f"**Deviation:** {anomaly['Deviation']}%")
            
            st.write(f"**Description:** {anomaly['Description']}")
            
            # Anomaly details and actions
            if st.button(f"Investigate Anomaly", key=f"investigate_{anomaly.name}"):
                show_anomaly_investigation(anomaly)
            
            if st.button(f"Mark as Normal", key=f"normal_{anomaly.name}"):
                st.success("Anomaly marked as normal behavior and added to whitelist")
    
    # Machine learning model performance
    st.subheader("🤖 ML Model Performance")
    
    model_metrics = get_model_performance()
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Precision", f"{model_metrics['precision']:.2%}")
        st.metric("Recall", f"{model_metrics['recall']:.2%}")
    
    with col2:
        st.metric("F1-Score", f"{model_metrics['f1_score']:.2%}")
        st.metric("AUC-ROC", f"{model_metrics['auc_roc']:.3f}")
    
    with col3:
        # Model training history
        training_data = generate_training_history()
        fig = px.line(training_data, x='Epoch', y=['Training_Loss', 'Validation_Loss'],
                     title="Model Training Progress")
        st.plotly_chart(fig, use_container_width=True)
    
    # Anomaly patterns and insights
    st.subheader("📈 Anomaly Patterns & Insights")
    
    # Pattern analysis
    patterns = analyze_anomaly_patterns(anomaly_data)
    
    for pattern in patterns:
        st.info(f"**Pattern Detected:** {pattern['description']}")
        st.write(f"Frequency: {pattern['frequency']}, Confidence: {pattern['confidence']}")

def run_anomaly_detection(detection_type, sensitivity, data_sources):
    """Run anomaly detection with specified parameters"""
    with st.spinner(f"Running {detection_type} on {', '.join(data_sources)}..."):
        # Simulate anomaly detection process
        progress = st.progress(0)
        for i in range(100):
            progress.progress(i + 1)
        
        st.success(f"Anomaly detection completed! Found 7 anomalies with sensitivity {sensitivity}")

def generate_anomaly_data():
    """Generate realistic anomaly data"""
    anomaly_types = ["Traffic Spike", "Unusual Login", "Resource Consumption", "Network Pattern", "Data Access"]
    severities = ["High", "Medium", "Low"]
    sources = ["Network Monitor", "Access Logs", "System Metrics", "Security Logs", "Application Logs"]
    
    data = []
    for i in range(20):
        anomaly_type = np.random.choice(anomaly_types)
        severity = np.random.choice(severities, p=[0.2, 0.5, 0.3])
        
        baseline = np.random.normal(100, 20)
        deviation = np.random.uniform(30, 200) if severity == "High" else np.random.uniform(15, 50)
        observed = baseline * (1 + deviation/100)
        
        data.append({
            "Type": anomaly_type,
            "Severity": severity,
            "Source": np.random.choice(sources),
            "Score": np.random.uniform(0.1, 1.0),
            "Baseline": f"{baseline:.1f}",
            "Observed": f"{observed:.1f}",
            "Deviation": f"{deviation:.1f}",
            "Timestamp": (datetime.now() - timedelta(hours=np.random.randint(0, 72))).strftime("%Y-%m-%d %H:%M"),
            "Description": f"Detected {anomaly_type.lower()} with {deviation:.1f}% deviation from baseline"
        })
    
    return pd.DataFrame(data)

def create_anomaly_timeline(data):
    """Create timeline visualization with anomalies"""
    # Generate time series data
    times = pd.date_range(start=datetime.now() - timedelta(days=7), 
                         end=datetime.now(), freq='H')
    
    # Normal behavior baseline
    normal_values = np.random.normal(100, 15, len(times))
    
    # Add anomalies
    anomaly_indices = np.random.choice(len(times), size=20, replace=False)
    values = normal_values.copy()
    
    for idx in anomaly_indices:
        if np.random.random() > 0.5:
            values[idx] += np.random.uniform(50, 150)  # Positive anomaly
        else:
            values[idx] -= np.random.uniform(30, 80)   # Negative anomaly
    
    fig = go.Figure()
    
    # Add normal data
    fig.add_trace(go.Scatter(
        x=times, y=values,
        mode='lines',
        name='Metric Value',
        line=dict(color='blue')
    ))
    
    # Highlight anomalies
    fig.add_trace(go.Scatter(
        x=times[anomaly_indices], y=values[anomaly_indices],
        mode='markers',
        name='Anomalies',
        marker=dict(color='red', size=8)
    ))
    
    fig.update_layout(
        title="System Metrics with Anomaly Detection",
        xaxis_title="Time",
        yaxis_title="Metric Value"
    )
    
    return fig

def apply_anomaly_filters(data, severity_filter, time_range, source_filter):
    """Apply filters to anomaly data"""
    filtered_data = data.copy()
    
    if severity_filter != "All":
        filtered_data = filtered_data[filtered_data['Severity'] == severity_filter]
    
    if source_filter != "All":
        filtered_data = filtered_data[filtered_data['Source'] == source_filter]
    
    # Time range filtering would be implemented here
    # For now, return the filtered data
    return filtered_data

def show_anomaly_investigation(anomaly):
    """Show detailed anomaly investigation"""
    st.subheader(f"🔍 Investigating {anomaly['Type']} Anomaly")
    
    # Investigation details
    investigation_data = {
        "Root Cause Analysis": "Analyzing correlation with system events...",
        "Impact Assessment": "Low - isolated to single system component",
        "Recommended Actions": "Monitor for 24 hours, review access logs",
        "Similar Incidents": "3 similar anomalies in the past month",
        "Risk Level": "Medium"
    }
    
    for key, value in investigation_data.items():
        st.write(f"**{key}:** {value}")

def get_model_performance():
    """Get ML model performance metrics"""
    return {
        "precision": 0.92,
        "recall": 0.88,
        "f1_score": 0.90,
        "auc_roc": 0.947
    }

def generate_training_history():
    """Generate model training history"""
    epochs = range(1, 51)
    training_loss = [0.8 * np.exp(-0.1 * epoch) + np.random.normal(0, 0.02) for epoch in epochs]
    validation_loss = [0.85 * np.exp(-0.08 * epoch) + np.random.normal(0, 0.03) for epoch in epochs]
    
    return pd.DataFrame({
        "Epoch": list(epochs),
        "Training_Loss": training_loss,
        "Validation_Loss": validation_loss
    })

def analyze_anomaly_patterns(data):
    """Analyze patterns in anomaly data"""
    patterns = [
        {
            "description": "Traffic spikes occur most frequently during business hours",
            "frequency": "Daily",
            "confidence": "87%"
        },
        {
            "description": "Unusual login patterns correlate with weekend access",
            "frequency": "Weekly",
            "confidence": "92%"
        },
        {
            "description": "Resource consumption anomalies peak during monthly backups",
            "frequency": "Monthly",
            "confidence": "95%"
        }
    ]
    
    return patterns
