-- 🚨 CORE-DEV PostgreSQL Schema
-- Nuclear-grade database schema for development environment
-- Compliance: ISO 27001 + GDPR + Zero Trust
-- Classification: CONFIDENTIAL
-- Review Date: Every 3 months

-- Create database if not exists (run as superuser)
-- CREATE DATABASE "core-dev" WITH ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8';

-- Connect to core-dev database
-- \c core-dev;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For text search optimization

-- =====================================================
-- SCHEMA: Multi-tenant isolation with schema separation
-- =====================================================
CREATE SCHEMA IF NOT EXISTS core_dev;
SET search_path TO core_dev, public;

-- =====================================================
-- ENUM TYPES for compliance and consistency
-- =====================================================

-- Log levels enum
CREATE TYPE log_level AS ENUM (
    'debug',
    'info',
    'warn',
    'error',
    'critical'
);

-- Classification levels (ISO 27001 A.8.2.1)
CREATE TYPE classification_level AS ENUM (
    'public',
    'internal',
    'confidential',
    'restricted'
);

-- Audit event outcomes
CREATE TYPE audit_outcome AS ENUM (
    'SUCCESS',
    'FAILURE',
    'PARTIAL'
);

-- =====================================================
-- MAIN LOGS TABLE
-- Primary log ingestion table with compliance fields
-- =====================================================
CREATE TABLE IF NOT EXISTS logs (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,
    
    -- Multi-tenant fields (HIGH classification)
    tenant_name VARCHAR(64) NOT NULL,
    
    -- Core log fields (INTERNAL classification)
    service VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    level log_level NOT NULL,
    message TEXT NOT NULL,
    
    -- Tracing and correlation (INTERNAL classification)
    trace_id UUID DEFAULT uuid_generate_v4(),
    correlation_id VARCHAR(128),
    
    -- Classification for compliance (MANDATORY)
    classification classification_level NOT NULL DEFAULT 'internal',
    
    -- Structured data (varies by classification)
    tags TEXT[] DEFAULT '{}',
    context JSONB DEFAULT '{}',
    
    -- Retention management (GDPR Article 17)
    retention_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Indexes for performance
    CONSTRAINT logs_tenant_service_idx UNIQUE (id, tenant_name, service)
);

-- Performance indexes
CREATE INDEX idx_logs_tenant_timestamp ON logs(tenant_name, timestamp DESC);
CREATE INDEX idx_logs_service_level ON logs(service, level);
CREATE INDEX idx_logs_trace_id ON logs(trace_id);
CREATE INDEX idx_logs_retention ON logs(retention_until);
CREATE INDEX idx_logs_classification ON logs(classification);
CREATE INDEX idx_logs_tags ON logs USING GIN(tags);
CREATE INDEX idx_logs_context ON logs USING GIN(context);

-- Full text search on message
CREATE INDEX idx_logs_message_fts ON logs USING GIN(to_tsvector('english', message));

-- =====================================================
-- AUDIT LOGS TABLE
-- Comprehensive audit trail (ISO 27001 A.12.4.1)
-- =====================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,
    
    -- Event identification
    event_type VARCHAR(100) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    correlation_id VARCHAR(128) NOT NULL,
    
    -- Subject (who)
    user_id VARCHAR(128),
    user_role VARCHAR(64),
    service_account VARCHAR(128),
    
    -- Object (what)
    resource_type VARCHAR(100),
    resource_id VARCHAR(256),
    tenant_name VARCHAR(64),
    
    -- Action details
    action TEXT NOT NULL,
    outcome audit_outcome NOT NULL,
    
    -- Context (how/where/when)
    source_ip INET,
    user_agent TEXT,
    session_id VARCHAR(128),
    request_id VARCHAR(128),
    
    -- Technical details
    method VARCHAR(10),
    endpoint VARCHAR(512),
    status_code INTEGER,
    duration_ms INTEGER,
    
    -- Security context
    classification classification_level NOT NULL DEFAULT 'high',
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 10),
    threat_indicators TEXT[],
    
    -- Compliance context
    data_categories TEXT[],
    legal_basis VARCHAR(100),
    retention_period INTEGER,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    -- Retention (7 years for audit trails)
    retention_until TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 years',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes for audit logs
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_name);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_correlation ON audit_logs(correlation_id);
CREATE INDEX idx_audit_logs_risk ON audit_logs(risk_score) WHERE risk_score >= 6;
CREATE INDEX idx_audit_logs_outcome ON audit_logs(outcome);
CREATE INDEX idx_audit_logs_retention ON audit_logs(retention_until);

-- =====================================================
-- ERROR LOGS TABLE
-- Detailed error tracking for troubleshooting
-- =====================================================
CREATE TABLE IF NOT EXISTS error_logs (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,
    
    -- Error identification
    error_id UUID DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Error details
    error_type VARCHAR(100) NOT NULL,
    error_message TEXT NOT NULL,
    error_code VARCHAR(50),
    stack_trace TEXT,
    
    -- Context
    service VARCHAR(64) NOT NULL,
    tenant_name VARCHAR(64),
    correlation_id VARCHAR(128),
    user_id VARCHAR(128),
    
    -- Request context
    method VARCHAR(10),
    endpoint VARCHAR(512),
    request_body JSONB,
    request_headers JSONB,
    
    -- Classification and severity
    classification classification_level NOT NULL DEFAULT 'internal',
    severity VARCHAR(20) NOT NULL,
    
    -- Additional context
    metadata JSONB DEFAULT '{}',
    
    -- Retention (3 years for error logs)
    retention_until TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '3 years',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes for error logs
CREATE INDEX idx_error_logs_timestamp ON error_logs(timestamp DESC);
CREATE INDEX idx_error_logs_service ON error_logs(service);
CREATE INDEX idx_error_logs_tenant ON error_logs(tenant_name);
CREATE INDEX idx_error_logs_correlation ON error_logs(correlation_id);
CREATE INDEX idx_error_logs_severity ON error_logs(severity);
CREATE INDEX idx_error_logs_retention ON error_logs(retention_until);

-- =====================================================
-- SECURITY EVENTS TABLE
-- Security-specific events for threat monitoring
-- =====================================================
CREATE TABLE IF NOT EXISTS security_events (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,
    
    -- Event identification
    event_id UUID DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Security event details
    event_type VARCHAR(100) NOT NULL,
    threat_level VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    description TEXT NOT NULL,
    
    -- Actor information
    source_ip INET,
    user_agent TEXT,
    user_id VARCHAR(128),
    tenant_name VARCHAR(64),
    
    -- Attack details
    attack_vector VARCHAR(100),
    attack_pattern TEXT,
    blocked BOOLEAN DEFAULT FALSE,
    
    -- Impact assessment
    affected_resources TEXT[],
    potential_impact TEXT,
    
    -- Response actions
    actions_taken TEXT[],
    mitigation_status VARCHAR(50),
    
    -- Additional context
    metadata JSONB DEFAULT '{}',
    correlation_id VARCHAR(128),
    
    -- Retention (10 years for security events)
    retention_until TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 years',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes for security events
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_threat ON security_events(threat_level);
CREATE INDEX idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX idx_security_events_tenant ON security_events(tenant_name);
CREATE INDEX idx_security_events_blocked ON security_events(blocked);
CREATE INDEX idx_security_events_retention ON security_events(retention_until);

-- =====================================================
-- METRICS TABLE
-- Performance and business metrics storage
-- =====================================================
CREATE TABLE IF NOT EXISTS metrics (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,
    
    -- Metric identification
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metric_name VARCHAR(128) NOT NULL,
    metric_value NUMERIC NOT NULL,
    metric_unit VARCHAR(50),
    
    -- Context
    service VARCHAR(64) NOT NULL,
    tenant_name VARCHAR(64),
    hostname VARCHAR(256),
    
    -- Dimensions (tags for grouping)
    dimensions JSONB DEFAULT '{}',
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Retention (90 days for metrics)
    retention_until TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '90 days',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes for metrics
CREATE INDEX idx_metrics_timestamp ON metrics(timestamp DESC);
CREATE INDEX idx_metrics_name_time ON metrics(metric_name, timestamp DESC);
CREATE INDEX idx_metrics_service ON metrics(service);
CREATE INDEX idx_metrics_tenant ON metrics(tenant_name);
CREATE INDEX idx_metrics_dimensions ON metrics USING GIN(dimensions);
CREATE INDEX idx_metrics_retention ON metrics(retention_until);

-- =====================================================
-- HEARTBEAT TABLE
-- Service health monitoring
-- =====================================================
CREATE TABLE IF NOT EXISTS heartbeats (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,
    
    -- Service identification
    client_id VARCHAR(64) NOT NULL,
    service VARCHAR(64) NOT NULL,
    hostname VARCHAR(256),
    
    -- Status information
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL, -- OK, STARTUP, WARNING, ERROR, SHUTDOWN
    
    -- Health metrics
    uptime_seconds INTEGER,
    memory_usage_mb INTEGER,
    cpu_usage_percent NUMERIC(5,2),
    active_connections INTEGER,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    -- Retention (7 days for heartbeats)
    retention_until TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes for heartbeats
CREATE INDEX idx_heartbeats_timestamp ON heartbeats(timestamp DESC);
CREATE INDEX idx_heartbeats_service ON heartbeats(service, timestamp DESC);
CREATE INDEX idx_heartbeats_client ON heartbeats(client_id);
CREATE INDEX idx_heartbeats_status ON heartbeats(status);
CREATE INDEX idx_heartbeats_retention ON heartbeats(retention_until);

-- =====================================================
-- USER SESSIONS TABLE
-- Authentication session tracking
-- =====================================================
CREATE TABLE IF NOT EXISTS user_sessions (
    -- Primary key
    session_id VARCHAR(128) PRIMARY KEY,
    
    -- User information
    user_id VARCHAR(128) NOT NULL,
    username VARCHAR(128) NOT NULL,
    tenant_name VARCHAR(64) NOT NULL,
    
    -- Session details
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Security context
    ip_address INET,
    user_agent TEXT,
    
    -- Session data
    roles TEXT[] DEFAULT '{}',
    permissions TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT
);

-- Performance indexes for sessions
CREATE INDEX idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_sessions_tenant ON user_sessions(tenant_name);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX idx_sessions_active ON user_sessions(is_active) WHERE is_active = TRUE;

-- =====================================================
-- RATE LIMIT TABLE
-- API rate limiting tracking
-- =====================================================
CREATE TABLE IF NOT EXISTS rate_limits (
    -- Composite primary key
    identifier VARCHAR(256) NOT NULL, -- IP or user_id
    endpoint VARCHAR(256) NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    
    -- Rate limit data
    request_count INTEGER NOT NULL DEFAULT 1,
    
    -- Context
    tenant_name VARCHAR(64),
    
    -- Primary key
    PRIMARY KEY (identifier, endpoint, window_start)
);

-- Performance indexes for rate limits
CREATE INDEX idx_rate_limits_identifier ON rate_limits(identifier);
CREATE INDEX idx_rate_limits_window ON rate_limits(window_start);

-- =====================================================
-- COMPLIANCE RECORDS TABLE
-- GDPR and compliance tracking
-- =====================================================
CREATE TABLE IF NOT EXISTS compliance_records (
    -- Primary key
    id BIGSERIAL PRIMARY KEY,
    
    -- Record identification
    record_type VARCHAR(100) NOT NULL, -- DATA_REQUEST, DATA_DELETION, CONSENT, etc.
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Subject information
    data_subject_id VARCHAR(128),
    tenant_name VARCHAR(64),
    
    -- Request details
    request_type VARCHAR(50),
    request_details JSONB,
    legal_basis VARCHAR(100),
    
    -- Processing information
    processed_at TIMESTAMPTZ,
    processed_by VARCHAR(128),
    outcome VARCHAR(50),
    
    -- Audit trail
    actions_taken TEXT[],
    affected_records JSONB,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Retention (10 years for compliance records)
    retention_until TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 years',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Performance indexes for compliance records
CREATE INDEX idx_compliance_timestamp ON compliance_records(timestamp DESC);
CREATE INDEX idx_compliance_type ON compliance_records(record_type);
CREATE INDEX idx_compliance_subject ON compliance_records(data_subject_id);
CREATE INDEX idx_compliance_tenant ON compliance_records(tenant_name);
CREATE INDEX idx_compliance_retention ON compliance_records(retention_until);

-- =====================================================
-- FUNCTIONS AND TRIGGERS
-- =====================================================

-- Function to automatically set retention_until based on classification
CREATE OR REPLACE FUNCTION set_retention_period()
RETURNS TRIGGER AS $$
BEGIN
    -- Only set if retention_until is not already specified
    IF NEW.retention_until IS NULL THEN
        CASE NEW.classification
            WHEN 'public' THEN
                NEW.retention_until := NEW.created_at + INTERVAL '30 days';
            WHEN 'internal' THEN
                NEW.retention_until := NEW.created_at + INTERVAL '365 days';
            WHEN 'confidential' THEN
                NEW.retention_until := NEW.created_at + INTERVAL '7 years';
            WHEN 'restricted' THEN
                NEW.retention_until := NEW.created_at + INTERVAL '10 years';
            ELSE
                NEW.retention_until := NEW.created_at + INTERVAL '1 year';
        END CASE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply retention trigger to logs table
CREATE TRIGGER set_log_retention
    BEFORE INSERT ON logs
    FOR EACH ROW
    EXECUTE FUNCTION set_retention_period();

-- Function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS void AS $$
BEGIN
    UPDATE user_sessions
    SET is_active = FALSE
    WHERE expires_at < NOW() AND is_active = TRUE;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- ROW LEVEL SECURITY (RLS)
-- Multi-tenant data isolation
-- =====================================================

-- Enable RLS on main tables
ALTER TABLE logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE error_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE metrics ENABLE ROW LEVEL SECURITY;

-- Create application role
CREATE ROLE core_app_user;

-- RLS Policies for logs table
CREATE POLICY tenant_isolation_logs ON logs
    FOR ALL
    TO core_app_user
    USING (tenant_name = current_setting('app.current_tenant', TRUE));

-- RLS Policies for audit_logs table
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
    FOR ALL
    TO core_app_user
    USING (tenant_name = current_setting('app.current_tenant', TRUE));

-- RLS Policies for error_logs table
CREATE POLICY tenant_isolation_error_logs ON error_logs
    FOR ALL
    TO core_app_user
    USING (tenant_name = current_setting('app.current_tenant', TRUE));

-- RLS Policies for metrics table
CREATE POLICY tenant_isolation_metrics ON metrics
    FOR ALL
    TO core_app_user
    USING (tenant_name = current_setting('app.current_tenant', TRUE));

-- =====================================================
-- VIEWS FOR COMMON QUERIES
-- =====================================================

-- Recent logs view (last 24 hours)
CREATE OR REPLACE VIEW recent_logs AS
SELECT 
    id,
    tenant_name,
    service,
    timestamp,
    level,
    message,
    trace_id,
    classification
FROM logs
WHERE timestamp > NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;

-- Active sessions view
CREATE OR REPLACE VIEW active_sessions AS
SELECT 
    session_id,
    user_id,
    username,
    tenant_name,
    created_at,
    expires_at,
    last_activity,
    ip_address
FROM user_sessions
WHERE is_active = TRUE AND expires_at > NOW();

-- High risk security events
CREATE OR REPLACE VIEW high_risk_security_events AS
SELECT 
    event_id,
    timestamp,
    event_type,
    threat_level,
    description,
    source_ip,
    tenant_name,
    blocked
FROM security_events
WHERE threat_level IN ('HIGH', 'CRITICAL')
    AND timestamp > NOW() - INTERVAL '7 days'
ORDER BY timestamp DESC;

-- =====================================================
-- GRANTS
-- =====================================================

-- Grant permissions to application role
GRANT USAGE ON SCHEMA core_dev TO core_app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core_dev TO core_app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA core_dev TO core_app_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA core_dev TO core_app_user;

-- =====================================================
-- MAINTENANCE QUERIES (Run periodically)
-- =====================================================

-- Query to delete expired data (run daily)
/*
DELETE FROM logs WHERE retention_until < NOW();
DELETE FROM audit_logs WHERE retention_until < NOW();
DELETE FROM error_logs WHERE retention_until < NOW();
DELETE FROM security_events WHERE retention_until < NOW();
DELETE FROM metrics WHERE retention_until < NOW();
DELETE FROM heartbeats WHERE retention_until < NOW();
DELETE FROM rate_limits WHERE window_start < NOW() - INTERVAL '1 hour';
*/

-- Query to analyze table sizes
/*
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'core_dev'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
*/

-- =====================================================
-- SAMPLE DATA FOR TESTING (DEVELOPMENT ONLY)
-- =====================================================

-- Insert test log entries
/*
INSERT INTO logs (tenant_name, service, level, message, classification, tags, context)
VALUES 
    ('core-dev', 'auth-service', 'info', 'User login successful', 'internal', 
     ARRAY['auth', 'login'], '{"user_id": "dev-user-001", "ip": "127.0.0.1"}'),
    ('core-dev', 'api-gateway', 'warn', 'Rate limit approaching', 'internal',
     ARRAY['rate-limit', 'warning'], '{"endpoint": "/api/emit-log", "current": 95, "limit": 100}'),
    ('core-dev', 'pdf-service', 'error', 'PDF generation failed', 'confidential',
     ARRAY['pdf', 'error'], '{"document_id": "DOC-123", "error": "Template not found"}');
*/