-- CyberShield AI Platform Database Initialization
-- This script sets up the initial database schema and security configurations

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create cybershield database user with appropriate permissions
-- (This will be run as postgres user during container initialization)

-- Set up database encoding and locale
ALTER DATABASE cybershield SET timezone TO 'UTC';

-- Create schema for CyberShield platform
CREATE SCHEMA IF NOT EXISTS cybershield AUTHORIZATION cybershield;

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON SCHEMA cybershield TO cybershield;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cybershield TO cybershield;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA cybershield TO cybershield;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA cybershield TO cybershield;

-- Set default schema for cybershield user
ALTER USER cybershield SET search_path TO cybershield, public;

-- Log successful initialization
INSERT INTO pg_stat_statements_info (dealloc) VALUES (0) ON CONFLICT DO NOTHING;