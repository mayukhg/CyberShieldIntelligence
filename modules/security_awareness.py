"""
Gamified Security Awareness Dashboard
Interactive cybersecurity training platform with game mechanics, challenges, and progress tracking
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
from typing import Dict, List, Any, Optional
import json
import time

def show_security_awareness():
    """Main gamified security awareness dashboard"""
    st.header("🎮 Security Awareness Training")
    st.markdown("Level up your cybersecurity skills through interactive challenges and training")
    
    # Initialize user session data
    if 'user_profile' not in st.session_state:
        st.session_state.user_profile = initialize_user_profile()
    
    if 'completed_challenges' not in st.session_state:
        st.session_state.completed_challenges = []
    
    if 'daily_streak' not in st.session_state:
        st.session_state.daily_streak = 0
    
    # User profile sidebar
    show_user_profile_sidebar()
    
    # Main dashboard tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🏠 Dashboard", 
        "🎯 Challenges", 
        "📚 Learning Modules", 
        "🏆 Leaderboard", 
        "📊 Progress"
    ])
    
    with tab1:
        show_gamified_dashboard()
    
    with tab2:
        show_security_challenges()
    
    with tab3:
        show_learning_modules()
    
    with tab4:
        show_leaderboard()
    
    with tab5:
        show_progress_tracking()

def initialize_user_profile():
    """Initialize user profile with default values"""
    return {
        'name': 'Security Champion',
        'level': 1,
        'xp': 0,
        'total_score': 0,
        'badges': [],
        'rank': 'Novice',
        'join_date': datetime.now(),
        'last_activity': datetime.now(),
        'modules_completed': 0,
        'challenges_completed': 0,
        'streak_days': 0
    }

def show_user_profile_sidebar():
    """Display user profile in sidebar with progress indicators"""
    st.sidebar.markdown("---")
    st.sidebar.subheader("🛡️ Your Profile")
    
    profile = st.session_state.user_profile
    
    # Level progress bar
    xp_for_next_level = calculate_xp_for_level(profile['level'] + 1)
    xp_current_level = calculate_xp_for_level(profile['level'])
    xp_progress = profile['xp'] - xp_current_level
    xp_needed = xp_for_next_level - xp_current_level
    
    progress_percentage = min(xp_progress / xp_needed, 1.0) if xp_needed > 0 else 1.0
    
    st.sidebar.markdown(f"**Level {profile['level']} {profile['rank']}**")
    st.sidebar.progress(progress_percentage)
    st.sidebar.caption(f"XP: {profile['xp']} / {xp_for_next_level}")
    
    # Quick stats
    col1, col2 = st.sidebar.columns(2)
    with col1:
        st.metric("Score", profile['total_score'])
    with col2:
        st.metric("Streak", f"{profile['streak_days']}🔥")
    
    # Recent badges
    if profile['badges']:
        st.sidebar.markdown("**Recent Badges:**")
        for badge in profile['badges'][-3:]:  # Show last 3 badges
            st.sidebar.markdown(f"🏅 {badge}")

def show_gamified_dashboard():
    """Main gamified dashboard with overview"""
    profile = st.session_state.user_profile
    
    # Welcome message with personalization
    current_hour = datetime.now().hour
    if current_hour < 12:
        greeting = "Good morning"
    elif current_hour < 18:
        greeting = "Good afternoon"
    else:
        greeting = "Good evening"
    
    st.markdown(f"## {greeting}, {profile['name']}! 👋")
    st.markdown(f"**Level {profile['level']} {profile['rank']}** | Today's Goal: Complete 1 security challenge")
    
    # Daily objectives with progress
    st.subheader("🎯 Today's Objectives")
    
    objectives = [
        {"name": "Complete Security Quiz", "progress": 0.7, "xp": 50, "completed": False},
        {"name": "Read Phishing Article", "progress": 1.0, "xp": 25, "completed": True},
        {"name": "Practice Password Security", "progress": 0.3, "xp": 75, "completed": False},
        {"name": "Review Security Incident", "progress": 0.0, "xp": 100, "completed": False}
    ]
    
    for obj in objectives:
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            status_icon = "✅" if obj['completed'] else "🎯"
            st.markdown(f"{status_icon} **{obj['name']}**")
            st.progress(obj['progress'])
        
        with col2:
            st.markdown(f"**+{obj['xp']} XP**")
        
        with col3:
            if not obj['completed']:
                if st.button("Start", key=f"start_{obj['name']}"):
                    complete_objective(obj)

    # Quick action cards
    st.subheader("🚀 Quick Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🧠 Daily Quiz", use_container_width=True):
            st.session_state.current_action = "daily_quiz"
            st.rerun()
    
    with col2:
        if st.button("📖 Learn Topic", use_container_width=True):
            st.session_state.current_action = "learn_topic"
            st.rerun()
    
    with col3:
        if st.button("🎮 Mini Challenge", use_container_width=True):
            st.session_state.current_action = "mini_challenge"
            st.rerun()
    
    with col4:
        if st.button("👥 Team Challenge", use_container_width=True):
            st.session_state.current_action = "team_challenge"
            st.rerun()
    
    # Handle quick actions
    if hasattr(st.session_state, 'current_action'):
        handle_quick_action(st.session_state.current_action)
    
    # Achievement showcase
    show_recent_achievements()
    
    # Security tips with gamification
    show_security_tip_of_the_day()

def show_security_challenges():
    """Interactive security challenges with different difficulty levels"""
    st.subheader("🎯 Security Challenges")
    st.markdown("Complete challenges to earn XP, badges, and improve your security knowledge!")
    
    # Challenge categories
    col1, col2, col3 = st.columns(3)
    
    with col1:
        category = st.selectbox("Category", [
            "All Categories",
            "Password Security",
            "Phishing Detection", 
            "Social Engineering",
            "Malware Awareness",
            "Data Protection",
            "Network Security"
        ])
    
    with col2:
        difficulty = st.selectbox("Difficulty", [
            "All Levels",
            "Beginner 🟢",
            "Intermediate 🟡", 
            "Advanced 🔴",
            "Expert 🟣"
        ])
    
    with col3:
        status = st.selectbox("Status", [
            "All Challenges",
            "Available",
            "Completed",
            "Locked"
        ])
    
    # Challenge grid
    challenges = get_security_challenges()
    filtered_challenges = filter_challenges(challenges, category, difficulty, status)
    
    for i, challenge in enumerate(filtered_challenges):
        if i % 2 == 0:
            col1, col2 = st.columns(2)
            current_col = col1
        else:
            current_col = col2
        
        with current_col:
            create_challenge_card(challenge)

def create_challenge_card(challenge):
    """Create an interactive challenge card"""
    # Determine card styling based on status
    if challenge['completed']:
        border_color = "#28a745"  # Green for completed
        status_emoji = "✅"
    elif challenge['locked']:
        border_color = "#6c757d"  # Gray for locked
        status_emoji = "🔒"
    else:
        border_color = "#007bff"  # Blue for available
        status_emoji = "🎯"
    
    # Challenge card
    with st.container():
        st.markdown(f"""
        <div style="border: 2px solid {border_color}; border-radius: 10px; padding: 15px; margin: 10px 0;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h4>{status_emoji} {challenge['title']}</h4>
                <span style="background: {border_color}; color: white; padding: 4px 8px; border-radius: 15px; font-size: 12px;">
                    {challenge['difficulty']}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.markdown(f"**{challenge['description']}**")
            st.caption(f"Category: {challenge['category']} | Time: {challenge['duration']}")
        
        with col2:
            st.markdown(f"**+{challenge['xp']} XP**")
            if challenge['badge']:
                st.markdown(f"🏅 {challenge['badge']}")
        
        with col3:
            if challenge['completed']:
                st.success("Completed!")
            elif challenge['locked']:
                st.warning("Locked")
            else:
                if st.button("Start Challenge", key=f"challenge_{challenge['id']}"):
                    start_challenge(challenge)

def show_learning_modules():
    """Interactive learning modules with progress tracking"""
    st.subheader("📚 Learning Modules")
    st.markdown("Structured learning paths to build your cybersecurity expertise")
    
    # Learning paths
    learning_paths = get_learning_paths()
    
    for path in learning_paths:
        with st.expander(f"🛤️ {path['title']} ({path['progress']}% Complete)", expanded=False):
            
            # Path overview
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**{path['description']}**")
                st.progress(path['progress'] / 100)
                st.caption(f"Estimated time: {path['duration']} | Level: {path['level']}")
            
            with col2:
                st.metric("Total XP", path['total_xp'])
                st.metric("Modules", f"{path['completed_modules']}/{path['total_modules']}")
            
            # Modules in path
            st.markdown("**Modules:**")
            for module in path['modules']:
                module_icon = "✅" if module['completed'] else "📖" if module['available'] else "🔒"
                status_text = "Completed" if module['completed'] else "Available" if module['available'] else "Locked"
                
                col1, col2, col3 = st.columns([3, 1, 1])
                
                with col1:
                    st.markdown(f"{module_icon} **{module['name']}** - {status_text}")
                
                with col2:
                    st.markdown(f"+{module['xp']} XP")
                
                with col3:
                    if module['available'] and not module['completed']:
                        if st.button("Start", key=f"module_{module['id']}"):
                            start_learning_module(module)

def show_leaderboard():
    """Competitive leaderboard with different categories"""
    st.subheader("🏆 Leaderboard")
    st.markdown("See how you rank against other security champions!")
    
    # Leaderboard categories
    leaderboard_type = st.selectbox("Leaderboard Type", [
        "Overall Score",
        "This Week",
        "This Month", 
        "Challenge Master",
        "Learning Champion",
        "Streak Leader"
    ])
    
    # Generate leaderboard data
    leaderboard_data = generate_leaderboard_data(leaderboard_type)
    
    # Current user position
    user_position = find_user_position(leaderboard_data)
    if user_position:
        st.info(f"🎯 Your current position: #{user_position['rank']} with {user_position['score']} points")
    
    # Top performers
    st.markdown("### 🥇 Top Performers")
    
    for i, user in enumerate(leaderboard_data[:10]):
        # Medal icons
        if i == 0:
            medal = "🥇"
        elif i == 1:
            medal = "🥈"
        elif i == 2:
            medal = "🥉"
        else:
            medal = f"#{i+1}"
        
        col1, col2, col3, col4 = st.columns([1, 3, 2, 2])
        
        with col1:
            st.markdown(f"**{medal}**")
        
        with col2:
            st.markdown(f"**{user['name']}**")
            st.caption(f"Level {user['level']} {user['rank']}")
        
        with col3:
            st.markdown(f"**{user['score']:,} pts**")
        
        with col4:
            if user.get('badge'):
                st.markdown(f"🏅 {user['badge']}")

def show_progress_tracking():
    """Detailed progress tracking with analytics"""
    st.subheader("📊 Your Progress Analytics")
    
    profile = st.session_state.user_profile
    
    # Progress overview
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total XP", profile['xp'], "+150 this week")
    
    with col2:
        st.metric("Challenges Completed", profile['challenges_completed'], "+3 this week")
    
    with col3:
        st.metric("Learning Modules", profile['modules_completed'], "+2 this week")
    
    with col4:
        st.metric("Current Streak", f"{profile['streak_days']} days", "+1 today")
    
    # Progress charts
    col1, col2 = st.columns(2)
    
    with col1:
        # XP progression over time
        xp_data = generate_xp_progression_data()
        fig = px.line(xp_data, x='date', y='xp', title='XP Progression Over Time')
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Skills radar chart
        skills_data = get_user_skills_data()
        fig = go.Figure(data=go.Scatterpolar(
            r=list(skills_data.values()),
            theta=list(skills_data.keys()),
            fill='toself',
            name='Your Skills'
        ))
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 10]
                )),
            title="Security Skills Radar",
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Achievement timeline
    st.subheader("🏅 Achievement Timeline")
    achievements = get_user_achievements()
    
    for achievement in achievements:
        with st.container():
            col1, col2, col3 = st.columns([1, 4, 2])
            
            with col1:
                st.markdown(f"**{achievement['icon']}**")
            
            with col2:
                st.markdown(f"**{achievement['title']}**")
                st.caption(achievement['description'])
            
            with col3:
                st.caption(achievement['date'])

def handle_quick_action(action):
    """Handle quick action selections"""
    if action == "daily_quiz":
        show_daily_quiz()
    elif action == "learn_topic":
        show_topic_selector()
    elif action == "mini_challenge":
        show_mini_challenge()
    elif action == "team_challenge":
        show_team_challenge()

def show_daily_quiz():
    """Interactive daily security quiz"""
    st.subheader("🧠 Daily Security Quiz")
    
    quiz_question = get_daily_quiz_question()
    
    st.markdown(f"**Question:** {quiz_question['question']}")
    
    # Quiz options
    selected_answer = st.radio("Select your answer:", quiz_question['options'], key="daily_quiz_answer")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Submit Answer"):
            if selected_answer == quiz_question['correct_answer']:
                st.success("🎉 Correct! +25 XP earned!")
                award_xp(25)
                award_badge_if_eligible("Quiz Master")
            else:
                st.error(f"❌ Incorrect. The correct answer is: {quiz_question['correct_answer']}")
                st.info(quiz_question['explanation'])
    
    with col2:
        if st.button("Skip"):
            st.session_state.current_action = None
            st.rerun()

def show_recent_achievements():
    """Display recent achievements and badges"""
    st.subheader("🏅 Recent Achievements")
    
    recent_achievements = [
        {"icon": "🎯", "title": "Challenge Complete", "description": "Completed Phishing Detection challenge", "xp": 75},
        {"icon": "📚", "title": "Knowledge Seeker", "description": "Completed Password Security module", "xp": 50},
        {"icon": "🔥", "title": "Streak Master", "description": "Maintained 7-day learning streak", "xp": 100}
    ]
    
    for achievement in recent_achievements:
        with st.container():
            col1, col2, col3 = st.columns([1, 4, 1])
            
            with col1:
                st.markdown(f"## {achievement['icon']}")
            
            with col2:
                st.markdown(f"**{achievement['title']}**")
                st.caption(achievement['description'])
            
            with col3:
                st.markdown(f"**+{achievement['xp']} XP**")

def show_security_tip_of_the_day():
    """Display gamified security tip"""
    st.subheader("💡 Security Tip of the Day")
    
    tips = [
        {
            "tip": "Use a password manager to generate and store unique passwords for each account.",
            "category": "Password Security",
            "difficulty": "Beginner",
            "action": "Try creating a strong password now!",
            "xp": 10
        },
        {
            "tip": "Always verify the sender before clicking links in emails, even if they appear to be from trusted sources.",
            "category": "Phishing Prevention", 
            "difficulty": "Intermediate",
            "action": "Practice identifying phishing emails",
            "xp": 15
        }
    ]
    
    tip = np.random.choice(tips)
    
    with st.container():
        st.info(f"**{tip['tip']}**")
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.caption(f"Category: {tip['category']} | Level: {tip['difficulty']}")
        
        with col2:
            if st.button(tip['action']):
                award_xp(tip['xp'])
                st.success(f"Great! +{tip['xp']} XP earned!")
        
        with col3:
            st.markdown(f"**+{tip['xp']} XP**")

# Helper functions for gamification logic

def calculate_xp_for_level(level):
    """Calculate XP required for a given level"""
    return level * 100 + (level - 1) * 50

def award_xp(amount):
    """Award XP to user and check for level up"""
    st.session_state.user_profile['xp'] += amount
    st.session_state.user_profile['total_score'] += amount
    
    # Check for level up
    current_level = st.session_state.user_profile['level']
    xp_for_next = calculate_xp_for_level(current_level + 1)
    
    if st.session_state.user_profile['xp'] >= xp_for_next:
        st.session_state.user_profile['level'] += 1
        st.session_state.user_profile['rank'] = get_rank_for_level(st.session_state.user_profile['level'])
        st.balloons()
        st.success(f"🎉 Level Up! You are now Level {st.session_state.user_profile['level']} {st.session_state.user_profile['rank']}!")

def award_badge_if_eligible(badge_name):
    """Award badge if user is eligible"""
    if badge_name not in st.session_state.user_profile['badges']:
        st.session_state.user_profile['badges'].append(badge_name)
        st.success(f"🏅 New Badge Earned: {badge_name}!")

def get_rank_for_level(level):
    """Get rank title for level"""
    ranks = {
        1: "Novice", 2: "Apprentice", 3: "Guardian", 4: "Defender", 
        5: "Sentinel", 6: "Expert", 7: "Master", 8: "Champion", 
        9: "Elite", 10: "Legend"
    }
    return ranks.get(min(level, 10), "Legend")

def get_security_challenges():
    """Get available security challenges"""
    return [
        {
            "id": 1,
            "title": "Password Strength Analyzer",
            "description": "Learn to identify strong vs weak passwords",
            "category": "Password Security",
            "difficulty": "Beginner 🟢",
            "duration": "5 mins",
            "xp": 50,
            "badge": "Password Pro",
            "completed": False,
            "locked": False
        },
        {
            "id": 2,
            "title": "Phishing Email Detective",
            "description": "Identify phishing emails from legitimate ones",
            "category": "Phishing Detection",
            "difficulty": "Intermediate 🟡",
            "duration": "10 mins",
            "xp": 75,
            "badge": "Phishing Hunter",
            "completed": True,
            "locked": False
        },
        {
            "id": 3,
            "title": "Social Engineering Scenarios",
            "description": "Navigate complex social engineering attacks",
            "category": "Social Engineering",
            "difficulty": "Advanced 🔴",
            "duration": "15 mins",
            "xp": 100,
            "badge": "Social Guardian",
            "completed": False,
            "locked": True
        }
    ]

def get_learning_paths():
    """Get structured learning paths"""
    return [
        {
            "title": "Cybersecurity Fundamentals",
            "description": "Essential cybersecurity concepts for everyone",
            "progress": 60,
            "duration": "2 hours",
            "level": "Beginner",
            "total_xp": 300,
            "completed_modules": 3,
            "total_modules": 5,
            "modules": [
                {"id": 1, "name": "Introduction to Cybersecurity", "xp": 50, "completed": True, "available": True},
                {"id": 2, "name": "Password Security Basics", "xp": 60, "completed": True, "available": True},
                {"id": 3, "name": "Email Security", "xp": 70, "completed": True, "available": True},
                {"id": 4, "name": "Safe Web Browsing", "xp": 60, "completed": False, "available": True},
                {"id": 5, "name": "Mobile Security", "xp": 60, "completed": False, "available": False}
            ]
        }
    ]

def generate_leaderboard_data(leaderboard_type):
    """Generate leaderboard data"""
    names = ["Alex Chen", "Sarah Johnson", "Mike Rodriguez", "Emma Davis", "Security Champion", "James Wilson", "Lisa Park", "David Kim", "Anna Smith", "Tom Brown"]
    
    leaderboard = []
    for i, name in enumerate(names):
        leaderboard.append({
            "name": name,
            "score": np.random.randint(1000, 5000),
            "level": np.random.randint(1, 8),
            "rank": get_rank_for_level(np.random.randint(1, 8)),
            "badge": np.random.choice(["Password Pro", "Phishing Hunter", "Security Expert", None])
        })
    
    return sorted(leaderboard, key=lambda x: x['score'], reverse=True)

def find_user_position(leaderboard_data):
    """Find current user position in leaderboard"""
    for i, user in enumerate(leaderboard_data):
        if user['name'] == "Security Champion":
            return {"rank": i + 1, "score": user['score']}
    return None

def get_daily_quiz_question():
    """Get daily quiz question"""
    questions = [
        {
            "question": "Which of the following is the strongest password?",
            "options": ["password123", "P@ssw0rd!", "MyDog'sName2023!", "123456789"],
            "correct_answer": "MyDog'sName2023!",
            "explanation": "Longer passwords with a mix of characters, numbers, and symbols are strongest."
        },
        {
            "question": "What should you do if you receive a suspicious email?",
            "options": ["Click the link to verify", "Forward it to friends", "Report it as spam", "Reply asking for verification"],
            "correct_answer": "Report it as spam",
            "explanation": "Always report suspicious emails rather than interacting with them."
        }
    ]
    
    return np.random.choice(questions)

def generate_xp_progression_data():
    """Generate XP progression data for charts"""
    dates = pd.date_range(start=datetime.now()-timedelta(days=30), end=datetime.now(), freq='D')
    xp_values = np.cumsum(np.random.randint(10, 50, len(dates)))
    
    return pd.DataFrame({
        'date': dates,
        'xp': xp_values
    })

def get_user_skills_data():
    """Get user skills data for radar chart"""
    return {
        'Password Security': 8,
        'Phishing Detection': 6,
        'Social Engineering': 4,
        'Malware Awareness': 7,
        'Data Protection': 5,
        'Network Security': 3
    }

def get_user_achievements():
    """Get user achievement timeline"""
    return [
        {
            "icon": "🏅",
            "title": "First Challenge Complete",
            "description": "Completed your first security challenge",
            "date": "2 days ago"
        },
        {
            "icon": "📚",
            "title": "Knowledge Seeker",
            "description": "Completed 3 learning modules",
            "date": "1 week ago"
        },
        {
            "icon": "🔥",
            "title": "Streak Starter",
            "description": "Started your learning streak",
            "date": "2 weeks ago"
        }
    ]

def filter_challenges(challenges, category, difficulty, status):
    """Filter challenges based on selected criteria"""
    filtered = challenges
    
    if category != "All Categories":
        filtered = [c for c in filtered if c['category'] == category]
    
    if difficulty != "All Levels":
        filtered = [c for c in filtered if c['difficulty'] == difficulty]
    
    if status == "Available":
        filtered = [c for c in filtered if not c['completed'] and not c['locked']]
    elif status == "Completed":
        filtered = [c for c in filtered if c['completed']]
    elif status == "Locked":
        filtered = [c for c in filtered if c['locked']]
    
    return filtered

def start_challenge(challenge):
    """Start a security challenge"""
    st.success(f"🎯 Starting challenge: {challenge['title']}")
    st.info("Challenge content would be loaded here with interactive elements, quizzes, and simulations.")
    
    # Simulate challenge completion
    if st.button("Complete Challenge", key=f"complete_{challenge['id']}"):
        award_xp(challenge['xp'])
        if challenge['badge']:
            award_badge_if_eligible(challenge['badge'])
        st.session_state.user_profile['challenges_completed'] += 1
        st.balloons()
        st.success(f"🎉 Challenge completed! +{challenge['xp']} XP earned!")

def start_learning_module(module):
    """Start a learning module"""
    st.success(f"📚 Starting module: {module['name']}")
    st.info("Learning content would be displayed here with interactive lessons, videos, and assessments.")
    
    # Simulate module completion
    if st.button("Complete Module", key=f"complete_module_{module['id']}"):
        award_xp(module['xp'])
        st.session_state.user_profile['modules_completed'] += 1
        st.success(f"🎉 Module completed! +{module['xp']} XP earned!")

def complete_objective(objective):
    """Complete a daily objective"""
    award_xp(objective['xp'])
    st.success(f"✅ Objective completed! +{objective['xp']} XP earned!")
    objective['completed'] = True
    objective['progress'] = 1.0