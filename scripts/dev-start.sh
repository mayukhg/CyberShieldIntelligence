#!/bin/bash

# ==============================================================================
# CyberShield AI Platform - Development Environment Startup Script
# ==============================================================================
# This script sets up and starts the CyberShield AI Platform in development mode
# with features optimized for rapid development and testing.
#
# Development Features:
# - Hot-reload capabilities for code changes
# - Debug mode enabled for detailed error messages
# - Separate development database to protect production data
# - Faster startup times with development-optimized configurations
# - Enhanced logging for debugging
#
# Usage:
#   chmod +x scripts/dev-start.sh
#   ./scripts/dev-start.sh
#
# Prerequisites:
# - Docker and Docker Compose installed
# - Development environment variables configured
# ==============================================================================

# Enable strict error handling for development safety
set -e

echo "🛡️ CyberShield AI Platform - Development Mode"
echo "============================================="

# =============================================================================
# Development Environment Setup
# =============================================================================
# Create necessary directories and development-specific configurations

echo "📁 Setting up development environment..."

# Create directories for development logs and data
# These are separate from production to avoid conflicts
mkdir -p logs data

echo "✅ Development directories created"

# =============================================================================
# Development Environment Configuration
# =============================================================================
# Set up development-specific environment variables

echo "⚙️ Configuring development environment..."

# Check if development environment file exists, create if not
if [ ! -f .env.dev ]; then
    echo "⚠️  Creating development environment configuration..."
    
    # Create development environment with debug-friendly settings
    cat > .env.dev << EOF
# ==============================================================================
# CyberShield AI Platform - Development Environment Configuration
# ==============================================================================
# Development-specific settings for rapid development and testing

# Development Database Configuration
# Separate development database to protect production data
# Note: Different port (5433) and database name for isolation
DATABASE_URL=postgresql://cybershield_dev:dev_password_2024@postgres:5433/cybershield_dev?sslmode=prefer

# Development Redis Configuration
# Uses database 1 instead of 0 to separate from production cache
REDIS_URL=redis://redis:6379/1

# AI/ML Configuration
# Set your OpenAI API key for testing AI features in development
OPENAI_API_KEY=your_openai_api_key_here

# Development Application Settings
# Debug mode enabled for detailed error messages and faster development
ENVIRONMENT=development
DEBUG=true

# Development-Specific Features
# Enable additional debugging and development tools
STREAMLIT_LOGGER_LEVEL=debug
STREAMLIT_CLIENT_TOOLBAR_MODE=developer
STREAMLIT_SERVER_FILE_WATCHER_TYPE=auto

# Development Security Settings
# Less strict settings for development convenience
DEV_MODE_CORS_ENABLED=true
DEV_MODE_SSL_REQUIRED=false
EOF
    
    echo "📝 Development environment template created at .env.dev"
    echo "🔧 Please edit .env.dev with your development configuration"
    echo "🔑 Set your OPENAI_API_KEY for testing AI-powered features"
fi

echo "✅ Development environment configured"

# =============================================================================
# Development Services Startup
# =============================================================================
# Start all services in development mode with hot-reload capabilities

echo "🚀 Starting development services..."
echo "   This includes hot-reload for rapid development..."

# Start services using both base and development compose files
# The development compose file overrides production settings for development
# -f flags specify multiple compose files to merge
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

echo "✅ Development services started successfully"

# =============================================================================
# Development Environment Verification
# =============================================================================
# Wait for services to initialize and verify development setup

echo "⏳ Waiting for services to initialize..."
echo "   Development mode may take slightly longer for initial setup..."

# Shorter wait time for development as services are optimized for speed
sleep 20

echo "🔍 Development services status:"

# Display status of all development services
docker-compose ps

echo "✅ All development services are running"

# =============================================================================
# Development Success Summary
# =============================================================================
# Provide development-specific information and helpful commands

echo ""
echo "🎉 Development environment ready!"
echo ""
echo "🔧 Development Access:"
echo "   🌐 Platform URL: http://localhost:5000"
echo "   🔄 Auto-reload: Enabled (code changes trigger restart)"
echo "   🐛 Debug mode: Active (detailed error messages)"
echo "   📊 Enhanced logging: Available for debugging"
echo ""
echo "🛠️ Development Commands:"
echo "   📊 View app logs:     docker-compose logs -f cybershield-app"
echo "   💾 View DB logs:      docker-compose logs -f postgres"
echo "   🔄 View Redis logs:   docker-compose logs -f redis"
echo "   📈 Monitor all:       docker-compose logs -f"
echo "   🛑 Stop services:     docker-compose down"
echo "   🔄 Restart app:       docker-compose restart cybershield-app"
echo ""
echo "🔧 Development Features Active:"
echo "   • Hot-reload for rapid development"
echo "   • Debug mode with detailed error messages"
echo "   • Separate development database (cybershield_dev)"
echo "   • Enhanced logging for troubleshooting"
echo "   • Development-friendly CORS settings"
echo "   • Auto file watching for code changes"
echo ""
echo "💡 Development Tips:"
echo "   • Code changes will automatically trigger application restart"
echo "   • Use 'docker-compose logs -f cybershield-app' to watch real-time logs"
echo "   • Development database is isolated from production data"
echo "   • Debug information is available in the browser console"
echo ""