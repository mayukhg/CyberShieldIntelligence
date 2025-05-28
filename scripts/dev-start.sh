#!/bin/bash

# CyberShield AI Platform - Development Environment Startup
set -e

echo "🛡️ CyberShield AI Platform - Development Mode"
echo "============================================="

# Create development environment
echo "📁 Setting up development environment..."
mkdir -p logs data

# Check if .env.dev exists, create if not
if [ ! -f .env.dev ]; then
    echo "⚠️  Creating development environment file..."
    cat > .env.dev << EOF
# CyberShield AI Platform - Development Environment
DATABASE_URL=postgresql://cybershield_dev:dev_password_2024@postgres:5433/cybershield_dev?sslmode=prefer
REDIS_URL=redis://redis:6379/1
OPENAI_API_KEY=your_openai_api_key_here
ENVIRONMENT=development
DEBUG=true
EOF
    echo "📝 Please edit .env.dev with your development configuration"
fi

# Start development services
echo "🚀 Starting development services..."
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

echo "⏳ Waiting for services to initialize..."
sleep 20

echo "🔍 Development services status:"
docker-compose ps

echo ""
echo "🎉 Development environment ready!"
echo "🌐 Access your platform at: http://localhost:5000"
echo "📊 View logs: docker-compose logs -f cybershield-app"
echo "🛑 Stop services: docker-compose down"
echo ""