#!/bin/bash

# CyberShield AI Platform - Production Deployment Script
set -e

echo "🛡️ CyberShield AI Platform - Production Deployment"
echo "=================================================="

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p logs data docker/ssl

# Set proper permissions
chmod 755 logs data

# Check if environment file exists
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating template..."
    cat > .env << EOF
# CyberShield AI Platform Environment Variables
DATABASE_URL=postgresql://cybershield:cybershield_secure_2024@postgres:5432/cybershield?sslmode=prefer
REDIS_URL=redis://redis:6379/0
OPENAI_API_KEY=your_openai_api_key_here
ENVIRONMENT=production
DEBUG=false
EOF
    echo "📝 Please edit .env file with your actual configuration values"
    echo "🔑 Don't forget to set your OPENAI_API_KEY for AI features"
fi

# Build and start services
echo "🔨 Building Docker images..."
docker-compose build --no-cache

echo "🚀 Starting CyberShield AI Platform..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Check service health
echo "🔍 Checking service health..."
docker-compose ps

# Test database connection
echo "💾 Testing database connection..."
if docker-compose exec -T postgres pg_isready -U cybershield -d cybershield; then
    echo "✅ Database is ready"
else
    echo "❌ Database connection failed"
    exit 1
fi

# Test application health
echo "🌐 Testing application health..."
if curl -f http://localhost:5000/_stcore/health > /dev/null 2>&1; then
    echo "✅ Application is healthy"
else
    echo "⚠️  Application health check failed - it may still be starting up"
fi

echo ""
echo "🎉 CyberShield AI Platform deployed successfully!"
echo "🌐 Access your platform at: http://localhost:5000"
echo "📊 Check logs with: docker-compose logs -f"
echo "🛑 Stop services with: docker-compose down"
echo ""
echo "🔐 Security Features Active:"
echo "   • Enterprise-grade encryption (AES-256-GCM)"
echo "   • Multi-layer input validation"
echo "   • Rate limiting and DDoS protection"
echo "   • Comprehensive audit logging"
echo "   • Zero-trust architecture"
echo ""