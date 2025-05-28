# ==============================================================================
# CyberShield AI Platform - Production Docker Image
# ==============================================================================
# This Dockerfile creates a production-ready container for the CyberShield AI
# Platform with enterprise-grade security hardening and optimizations.
#
# Security Features:
# - Non-root user execution for enhanced container security
# - Minimal base image to reduce attack surface
# - Multi-stage build capability for production optimization
# - Health checks for container monitoring
# ==============================================================================

# Use Python 3.11 slim image for minimal footprint and security
FROM python:3.11-slim

# Set environment variables for production optimization
# PYTHONUNBUFFERED: Ensures Python output is sent straight to terminal
# PYTHONDONTWRITEBYTECODE: Prevents Python from writing .pyc files
# PIP_NO_CACHE_DIR: Reduces image size by not caching pip downloads
# PIP_DISABLE_PIP_VERSION_CHECK: Skips pip version checks for faster builds
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create dedicated user and group for security best practices
# Running as non-root user prevents privilege escalation attacks
RUN groupadd -r cybershield && useradd -r -g cybershield cybershield

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies required for the application
# gcc/g++: Required for compiling Python packages with C extensions
# libpq-dev: PostgreSQL development libraries for database connectivity
# curl: Required for health checks and external API calls
# Clean up apt cache to reduce image size
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for optimal Docker layer caching
# This allows Docker to reuse the dependency installation layer
# when only application code changes
COPY pyproject.toml uv.lock ./

# Install Python dependencies
# Upgrade pip to latest version for security and performance
# Install application in editable mode for development flexibility
RUN pip install --upgrade pip && \
    pip install -e .

# Copy the entire application codebase to the container
# This includes all modules, utilities, and configuration files
COPY . .

# Create necessary directories for application data and logs
# Set proper ownership to the cybershield user for security
RUN mkdir -p /app/logs /app/data && \
    chown -R cybershield:cybershield /app

# Switch to non-root user for enhanced security
# All subsequent commands and the application will run as this user
USER cybershield

# Expose port 5000 for Streamlit application access
# This is the standard port for the CyberShield platform
EXPOSE 5000

# Configure health check for container monitoring
# Checks Streamlit's built-in health endpoint every 30 seconds
# Allows 5 seconds start period for application initialization
# Retries 3 times before marking container as unhealthy
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/_stcore/health || exit 1

# Define the default command to run the CyberShield AI Platform
# Streamlit configuration:
# - Runs on port 5000 for consistency with enterprise deployments
# - Binds to 0.0.0.0 to accept connections from outside the container
# - Disables CORS for internal network security
# - Disables XSRF protection as it's handled by the application layer
CMD ["streamlit", "run", "app.py", "--server.port", "5000", "--server.address", "0.0.0.0", "--server.enableCORS", "false", "--server.enableXsrfProtection", "false"]