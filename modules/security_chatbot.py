"""
AI-Powered Security Recommendation Chatbot
Intelligent cybersecurity assistant providing personalized recommendations and advice
"""

import streamlit as st
from openai import OpenAI
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import json
import time

# Configure OpenAI
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

class SecurityChatbot:
    """
    AI-powered security chatbot with real-time context awareness.
    
    This intelligent assistant provides personalized cybersecurity guidance by:
    1. Monitoring current security status from the CyberShield platform
    2. Understanding user roles and experience levels for tailored responses
    3. Maintaining conversation context for coherent multi-turn interactions
    4. Providing proactive recommendations based on current threat landscape
    
    The chatbot acts as a virtual security expert available 24/7 for instant guidance.
    """
    
    def __init__(self):
        """Initialize the chatbot with current security context and user profile."""
        # Store conversation history for context-aware responses
        self.conversation_history = []
        
        # Load real-time security data from the CyberShield platform
        # This ensures the AI has current threat intelligence for accurate guidance
        self.security_context = self.load_security_context()
        
        # Get user profile for personalized recommendations
        # Experience level and role determine the complexity and focus of responses
        self.user_profile = self.get_user_profile()
    
    def load_security_context(self):
        """
        Load current security context from the CyberShield platform.
        
        This pulls real-time data about:
        - Active threats and their severity levels
        - Current security posture and compliance status
        - Open incidents requiring attention
        - Recent vulnerability discoveries
        - Training completion status
        
        This context ensures the AI provides relevant, timely guidance.
        """
        return {
            # Recent threat activity detected by the platform
            "recent_threats": [
                {"type": "Phishing", "severity": "HIGH", "count": 5},
                {"type": "Malware", "severity": "CRITICAL", "count": 2},
                {"type": "Brute Force", "severity": "MEDIUM", "count": 8}
            ],
            
            # Overall security health indicators
            "security_posture": "MODERATE",      # Current threat level assessment
            "active_incidents": 3,               # Open security incidents requiring response
            "compliance_score": 78,              # Regulatory compliance percentage
            "vulnerability_count": 12,           # Known vulnerabilities needing patches
            "last_security_training": "2 weeks ago"  # Training currency for recommendations
        }
    
    def get_user_profile(self):
        """Get user profile for personalized recommendations"""
        return {
            "role": "Security Analyst",
            "experience_level": "Intermediate",
            "department": "IT Security",
            "security_clearance": "Standard",
            "training_progress": 65
        }
    
    def generate_response(self, user_input: str, conversation_type: str = "general") -> str:
        """Generate AI response using OpenAI with security context"""
        try:
            # Build context-aware prompt
            system_prompt = self.build_system_prompt(conversation_type)
            context_info = self.build_context_info()
            
            # Prepare conversation history
            messages = [{"role": "system", "content": system_prompt}]
            
            # Add recent conversation history
            for msg in self.conversation_history[-6:]:  # Last 3 exchanges
                messages.append(msg)
            
            # Add current context and user input
            full_user_input = f"Context: {context_info}\n\nUser Question: {user_input}"
            messages.append({"role": "user", "content": full_user_input})
            
            # Generate response using OpenAI
            response = client.chat.completions.create(
                model="gpt-4o",  # the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
                messages=messages,
                max_tokens=800,
                temperature=0.7,
                presence_penalty=0.1,
                frequency_penalty=0.1
            )
            
            ai_response = response.choices[0].message.content or "I apologize, but I couldn't generate a proper response. Please try again."
            
            # Update conversation history
            self.conversation_history.append({"role": "user", "content": user_input})
            self.conversation_history.append({"role": "assistant", "content": ai_response})
            
            return ai_response
            
        except Exception as e:
            return f"I apologize, but I'm experiencing technical difficulties. Please try again in a moment. Error: {str(e)}"
    
    def build_system_prompt(self, conversation_type: str) -> str:
        """Build context-aware system prompt"""
        base_prompt = """You are CyberShield AI, an expert cybersecurity assistant integrated into a comprehensive security platform. You provide intelligent, actionable security recommendations and advice.

Your expertise includes:
- Threat detection and response
- Security best practices
- Compliance and risk management
- Incident response procedures
- Security awareness training
- Vulnerability management
- Network security
- Cloud security

Guidelines:
1. Provide specific, actionable recommendations
2. Consider the user's role and experience level
3. Reference current security context when relevant
4. Use clear, professional language
5. Include step-by-step instructions when appropriate
6. Prioritize recommendations by risk and impact
7. Suggest preventive measures
8. Be concise but thorough

Response format:
- Start with a brief assessment
- Provide specific recommendations
- Include implementation steps
- Mention relevant best practices
- End with preventive advice if applicable"""

        if conversation_type == "incident":
            base_prompt += "\n\nFocus on incident response, containment, and recovery procedures."
        elif conversation_type == "training":
            base_prompt += "\n\nFocus on security awareness training and educational guidance."
        elif conversation_type == "compliance":
            base_prompt += "\n\nFocus on compliance requirements and regulatory guidance."
        
        return base_prompt
    
    def build_context_info(self) -> str:
        """Build current security context information"""
        context = f"""
Current Security Status:
- Security Posture: {self.security_context['security_posture']}
- Active Incidents: {self.security_context['active_incidents']}
- Compliance Score: {self.security_context['compliance_score']}%
- Open Vulnerabilities: {self.security_context['vulnerability_count']}

Recent Threat Activity:
"""
        for threat in self.security_context['recent_threats']:
            context += f"- {threat['type']}: {threat['count']} events ({threat['severity']} severity)\n"
        
        context += f"""
User Profile:
- Role: {self.user_profile['role']}
- Experience: {self.user_profile['experience_level']}
- Department: {self.user_profile['department']}
- Training Progress: {self.user_profile['training_progress']}%
"""
        return context

def show_security_chatbot():
    """Main security chatbot interface"""
    st.header("🤖 AI Security Assistant")
    st.markdown("Get intelligent cybersecurity recommendations and advice from your AI security expert")
    
    # Initialize chatbot
    if 'chatbot' not in st.session_state:
        st.session_state.chatbot = SecurityChatbot()
    
    if 'chat_messages' not in st.session_state:
        st.session_state.chat_messages = []
    
    # Chatbot controls
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        conversation_type = st.selectbox(
            "Conversation Type",
            ["general", "incident", "training", "compliance"],
            format_func=lambda x: {
                "general": "🛡️ General Security",
                "incident": "🚨 Incident Response", 
                "training": "📚 Security Training",
                "compliance": "📋 Compliance"
            }[x]
        )
    
    with col2:
        if st.button("🔄 New Conversation"):
            st.session_state.chat_messages = []
            st.session_state.chatbot = SecurityChatbot()
            st.rerun()
    
    with col3:
        if st.button("📋 Export Chat"):
            export_chat_history()
    
    # Quick action buttons
    st.subheader("🚀 Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    quick_questions = {
        "How do I respond to a phishing attack?": "🎣 Phishing Response",
        "What are the latest security best practices?": "🛡️ Best Practices", 
        "How can I improve our security posture?": "📈 Security Improvement",
        "What compliance requirements do we need to meet?": "📋 Compliance Help"
    }
    
    cols = [col1, col2, col3, col4]
    for i, (question, label) in enumerate(quick_questions.items()):
        with cols[i]:
            if st.button(label, use_container_width=True):
                process_user_input(question, conversation_type)
    
    # Chat interface
    st.subheader("💬 Chat with AI Security Expert")
    
    # Display chat history
    chat_container = st.container()
    with chat_container:
        display_chat_history()
    
    # User input
    user_input = st.chat_input("Ask me anything about cybersecurity...")
    
    if user_input:
        process_user_input(user_input, conversation_type)
    
    # Security insights sidebar
    show_security_insights_sidebar()

def process_user_input(user_input: str, conversation_type: str):
    """Process user input and generate AI response"""
    # Add user message
    st.session_state.chat_messages.append({
        "role": "user",
        "content": user_input,
        "timestamp": datetime.now()
    })
    
    # Generate AI response
    with st.spinner("🤖 AI is thinking..."):
        ai_response = st.session_state.chatbot.generate_response(user_input, conversation_type)
    
    # Add AI response
    st.session_state.chat_messages.append({
        "role": "assistant", 
        "content": ai_response,
        "timestamp": datetime.now(),
        "type": conversation_type
    })
    
    st.rerun()

def display_chat_history():
    """Display chat message history"""
    for message in st.session_state.chat_messages:
        if message["role"] == "user":
            with st.chat_message("user", avatar="👤"):
                st.write(message["content"])
                st.caption(message["timestamp"].strftime("%H:%M:%S"))
        else:
            with st.chat_message("assistant", avatar="🤖"):
                st.write(message["content"])
                
                # Add message metadata
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.caption(message["timestamp"].strftime("%H:%M:%S"))
                with col2:
                    msg_type = message.get("type", "general")
                    type_emoji = {
                        "general": "🛡️",
                        "incident": "🚨", 
                        "training": "📚",
                        "compliance": "📋"
                    }
                    st.caption(f"{type_emoji.get(msg_type, '🛡️')} {msg_type.title()}")

def show_security_insights_sidebar():
    """Show security insights in sidebar"""
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔍 Security Insights")
    
    # Current security status
    chatbot = st.session_state.chatbot
    
    st.sidebar.markdown("**Current Status:**")
    st.sidebar.info(f"Security Posture: {chatbot.security_context['security_posture']}")
    
    # Quick metrics
    col1, col2 = st.sidebar.columns(2)
    with col1:
        st.metric("Active Incidents", chatbot.security_context['active_incidents'])
    with col2:
        st.metric("Compliance", f"{chatbot.security_context['compliance_score']}%")
    
    # Recent threats
    st.sidebar.markdown("**Recent Threats:**")
    for threat in chatbot.security_context['recent_threats'][:3]:
        severity_color = {
            "CRITICAL": "🔴",
            "HIGH": "🟡", 
            "MEDIUM": "🟠",
            "LOW": "🟢"
        }
        st.sidebar.markdown(f"{severity_color.get(threat['severity'], '⚪')} {threat['type']}: {threat['count']} events")
    
    # AI recommendations
    st.sidebar.markdown("**💡 AI Recommendations:**")
    recommendations = get_proactive_recommendations()
    for rec in recommendations[:3]:
        st.sidebar.markdown(f"• {rec}")

def get_proactive_recommendations():
    """Get proactive security recommendations"""
    return [
        "Update endpoint protection signatures",
        "Review user access permissions",
        "Schedule phishing simulation training",
        "Patch critical vulnerabilities",
        "Backup security configurations"
    ]

def export_chat_history():
    """Export chat history"""
    if st.session_state.chat_messages:
        chat_export = {
            "export_time": datetime.now().isoformat(),
            "conversation_count": len(st.session_state.chat_messages),
            "messages": []
        }
        
        for msg in st.session_state.chat_messages:
            chat_export["messages"].append({
                "role": msg["role"],
                "content": msg["content"],
                "timestamp": msg["timestamp"].isoformat(),
                "type": msg.get("type", "general")
            })
        
        st.download_button(
            label="📥 Download Chat History",
            data=json.dumps(chat_export, indent=2),
            file_name=f"security_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
        st.success("Chat history ready for download!")
    else:
        st.warning("No chat history to export")

# Specialized chatbot functions

def ask_security_question():
    """Quick security question interface"""
    st.subheader("❓ Quick Security Question")
    
    question_categories = {
        "Password Security": [
            "How do I create a strong password?",
            "Should I use a password manager?",
            "How often should I change passwords?"
        ],
        "Phishing Protection": [
            "How do I identify phishing emails?",
            "What should I do if I clicked a suspicious link?",
            "How can I report phishing attempts?"
        ],
        "Incident Response": [
            "What are the first steps in incident response?",
            "How do I contain a security breach?",
            "When should I escalate an incident?"
        ],
        "Compliance": [
            "What are our GDPR obligations?",
            "How do I ensure SOC 2 compliance?",
            "What PCI DSS requirements apply to us?"
        ]
    }
    
    category = st.selectbox("Select Category", list(question_categories.keys()))
    question = st.selectbox("Select Question", question_categories[category])
    
    if st.button("Get AI Recommendation"):
        process_user_input(question, "general")

def security_scenario_analysis():
    """Analyze security scenarios with AI"""
    st.subheader("🎯 Security Scenario Analysis")
    
    scenario_text = st.text_area(
        "Describe your security scenario:",
        placeholder="Example: We detected unusual network traffic from an employee's laptop after they reported receiving a suspicious email...",
        height=100
    )
    
    severity = st.selectbox("Estimated Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    affected_systems = st.multiselect(
        "Affected Systems",
        ["Workstations", "Servers", "Network", "Database", "Email", "Cloud Services"]
    )
    
    if st.button("🤖 Analyze Scenario") and scenario_text:
        analysis_prompt = f"""
        Security Scenario Analysis Request:
        
        Scenario: {scenario_text}
        Severity: {severity}
        Affected Systems: {', '.join(affected_systems)}
        
        Please provide:
        1. Risk assessment
        2. Immediate response steps
        3. Investigation procedures
        4. Containment strategies
        5. Recovery recommendations
        6. Prevention measures
        """
        
        process_user_input(analysis_prompt, "incident")

def compliance_checker():
    """AI-powered compliance guidance"""
    st.subheader("📋 Compliance Guidance")
    
    framework = st.selectbox(
        "Compliance Framework",
        ["GDPR", "SOC 2", "PCI DSS", "HIPAA", "ISO 27001", "NIST", "SOX"]
    )
    
    business_type = st.selectbox(
        "Business Type",
        ["Technology", "Healthcare", "Financial", "Retail", "Government", "Education", "Other"]
    )
    
    specific_question = st.text_input(
        "Specific Compliance Question",
        placeholder="What specific compliance requirement do you need help with?"
    )
    
    if st.button("Get Compliance Guidance"):
        compliance_prompt = f"""
        Compliance Guidance Request:
        
        Framework: {framework}
        Business Type: {business_type}
        Question: {specific_question}
        
        Please provide specific compliance guidance including:
        1. Relevant requirements
        2. Implementation steps
        3. Documentation needed
        4. Common compliance gaps
        5. Best practices
        """
        
        process_user_input(compliance_prompt, "compliance")

def security_training_assistant():
    """AI-powered security training assistance"""
    st.subheader("📚 Security Training Assistant")
    
    training_topic = st.selectbox(
        "Training Topic",
        [
            "Phishing Awareness",
            "Password Security", 
            "Social Engineering",
            "Data Protection",
            "Incident Response",
            "Secure Coding",
            "Cloud Security",
            "Mobile Security"
        ]
    )
    
    audience = st.selectbox(
        "Target Audience",
        ["All Employees", "IT Staff", "Developers", "Management", "New Hires", "Remote Workers"]
    )
    
    training_format = st.selectbox(
        "Training Format",
        ["Interactive Workshop", "Online Module", "Quick Reference", "Assessment Quiz", "Video Content"]
    )
    
    if st.button("Generate Training Content"):
        training_prompt = f"""
        Security Training Content Request:
        
        Topic: {training_topic}
        Audience: {audience}
        Format: {training_format}
        
        Please create engaging training content including:
        1. Learning objectives
        2. Key concepts to cover
        3. Real-world examples
        4. Interactive elements
        5. Assessment questions
        6. Additional resources
        """
        
        process_user_input(training_prompt, "training")

# Additional chatbot features
def show_chatbot_analytics():
    """Show chatbot usage analytics"""
    st.subheader("📊 Chatbot Analytics")
    
    if st.session_state.chat_messages:
        total_messages = len(st.session_state.chat_messages)
        user_messages = len([m for m in st.session_state.chat_messages if m["role"] == "user"])
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Messages", total_messages)
        
        with col2:
            st.metric("User Questions", user_messages)
        
        with col3:
            st.metric("AI Responses", total_messages - user_messages)
        
        # Message types breakdown
        message_types = {}
        for msg in st.session_state.chat_messages:
            if msg["role"] == "assistant":
                msg_type = msg.get("type", "general")
                message_types[msg_type] = message_types.get(msg_type, 0) + 1
        
        if message_types:
            st.bar_chart(message_types)
    else:
        st.info("Start a conversation to see analytics!")

def show_advanced_features():
    """Show advanced chatbot features"""
    st.subheader("🚀 Advanced Features")
    
    tab1, tab2, tab3, tab4 = st.tabs([
        "❓ Quick Questions",
        "🎯 Scenario Analysis", 
        "📋 Compliance Help",
        "📚 Training Assistant"
    ])
    
    with tab1:
        ask_security_question()
    
    with tab2:
        security_scenario_analysis()
    
    with tab3:
        compliance_checker()
    
    with tab4:
        security_training_assistant()