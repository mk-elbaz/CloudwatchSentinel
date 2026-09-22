-- CloudWatch AI Sentinel Database Schema
-- Run this script to initialize the MySQL database

CREATE DATABASE IF NOT EXISTS cloudwatch_sentinel;
USE cloudwatch_sentinel;

-- Table for storing detected incidents
CREATE TABLE IF NOT EXISTS incidents (
    id VARCHAR(36) PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    log_group VARCHAR(255) NOT NULL,
    severity ENUM('CRITICAL', 'WARNING', 'INFO', 'NOISE') NOT NULL,
    summary TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    affected_service VARCHAR(255),
    raw_logs JSON,
    resolved BOOLEAN DEFAULT FALSE,
    occurrence_count INT DEFAULT 1,
    last_seen DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_log_group (log_group),
    INDEX idx_resolved (resolved)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for tracking analysis runs
CREATE TABLE IF NOT EXISTS analysis_runs (
    id VARCHAR(36) PRIMARY KEY,
    log_group VARCHAR(255) NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME NOT NULL,
    total_logs INT,
    incidents_found INT,
    duration_seconds FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for user-defined noise patterns to filter out
CREATE TABLE IF NOT EXISTS noise_patterns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pattern VARCHAR(500) NOT NULL,
    log_group VARCHAR(255),
    description TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_log_group (log_group)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert default noise patterns (only if they don't exist)
INSERT INTO noise_patterns (pattern, description) 
SELECT * FROM (SELECT 'Connection reset by peer' as pattern, 'Normal TCP connection close' as description) AS tmp
WHERE NOT EXISTS (
    SELECT pattern FROM noise_patterns WHERE pattern = 'Connection reset by peer'
) LIMIT 1;

INSERT INTO noise_patterns (pattern, description)
SELECT * FROM (SELECT 'Xray initialized', 'AWS X-Ray startup message') AS tmp
WHERE NOT EXISTS (
    SELECT pattern FROM noise_patterns WHERE pattern = 'Xray initialized'
) LIMIT 1;

INSERT INTO noise_patterns (pattern, description)
SELECT * FROM (SELECT 'Container terminated', 'Normal Lambda shutdown') AS tmp
WHERE NOT EXISTS (
    SELECT pattern FROM noise_patterns WHERE pattern = 'Container terminated'
) LIMIT 1;

INSERT INTO noise_patterns (pattern, description)
SELECT * FROM (SELECT 'SIGTERM received', 'Graceful shutdown signal') AS tmp
WHERE NOT EXISTS (
    SELECT pattern FROM noise_patterns WHERE pattern = 'SIGTERM received'
) LIMIT 1;

INSERT INTO noise_patterns (pattern, description)
SELECT * FROM (SELECT 'Deprecation warning', 'Non-critical deprecation notices') AS tmp
WHERE NOT EXISTS (
    SELECT pattern FROM noise_patterns WHERE pattern = 'Deprecation warning'
) LIMIT 1;

-- Table for website analytics (CloudFront logs)
CREATE TABLE IF NOT EXISTS website_analytics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL,
    unique_visitors INT DEFAULT 0,
    total_page_views INT DEFAULT 0,
    total_requests INT DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_date (date),
    INDEX idx_date (date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for top pages statistics
CREATE TABLE IF NOT EXISTS website_top_pages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL,
    uri VARCHAR(500) NOT NULL,
    views INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_date (date),
    INDEX idx_views (views)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for referrer statistics
CREATE TABLE IF NOT EXISTS website_referrers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    date DATE NOT NULL,
    referrer VARCHAR(500) NOT NULL,
    visits INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_date (date),
    INDEX idx_visits (visits)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- Security Analyzer Tables
-- ============================================

-- Table for security scan runs
CREATE TABLE IF NOT EXISTS security_scan_runs (
    id VARCHAR(36) PRIMARY KEY,
    scan_time DATETIME NOT NULL,
    total_findings INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    security_score INT DEFAULT 100,
    services_scanned JSON,
    ai_recommendations TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_scan_time (scan_time),
    INDEX idx_security_score (security_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for individual security findings
CREATE TABLE IF NOT EXISTS security_findings (
    id VARCHAR(36) PRIMARY KEY,
    scan_run_id VARCHAR(36),
    timestamp DATETIME NOT NULL,
    finding_type VARCHAR(100) NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL') NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    recommendation TEXT,
    additional_info JSON,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_scan_run (scan_run_id),
    INDEX idx_severity (severity),
    INDEX idx_resource_type (resource_type),
    INDEX idx_resolved (resolved),
    INDEX idx_finding_type (finding_type),
    FOREIGN KEY (scan_run_id) REFERENCES security_scan_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- Performance Analyzer Tables
-- ============================================

-- Table for performance analysis runs
CREATE TABLE IF NOT EXISTS performance_analysis_runs (
    id VARCHAR(36) PRIMARY KEY,
    analysis_time DATETIME NOT NULL,
    analysis_period_hours INT DEFAULT 24,
    total_resources INT DEFAULT 0,
    resources_with_issues INT DEFAULT 0,
    performance_score INT DEFAULT 100,
    services_analyzed JSON,
    ai_recommendations TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_analysis_time (analysis_time),
    INDEX idx_performance_score (performance_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for individual performance insights
CREATE TABLE IF NOT EXISTS performance_insights (
    id VARCHAR(36) PRIMARY KEY,
    analysis_run_id VARCHAR(36),
    timestamp DATETIME NOT NULL,
    service ENUM('Lambda', 'RDS', 'EC2', 'APIGateway') NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    insight_type VARCHAR(100) NOT NULL,
    severity ENUM('HIGH', 'MEDIUM', 'LOW', 'INFO') NOT NULL,
    metric_name VARCHAR(100),
    metric_value FLOAT,
    threshold FLOAT,
    message TEXT,
    suggestion TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_analysis_run (analysis_run_id),
    INDEX idx_service (service),
    INDEX idx_severity (severity),
    INDEX idx_insight_type (insight_type),
    FOREIGN KEY (analysis_run_id) REFERENCES performance_analysis_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- Resource Health Tables
-- ============================================

-- Table for health check runs
CREATE TABLE IF NOT EXISTS health_check_runs (
    id VARCHAR(36) PRIMARY KEY,
    check_time DATETIME NOT NULL,
    overall_score INT DEFAULT 100,
    overall_status ENUM('EXCELLENT', 'GOOD', 'FAIR', 'POOR', 'CRITICAL') NOT NULL,
    service_scores JSON,
    alarms_in_alarm INT DEFAULT 0,
    resources_unhealthy INT DEFAULT 0,
    ai_recommendations TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_check_time (check_time),
    INDEX idx_overall_score (overall_score),
    INDEX idx_overall_status (overall_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for individual resource health status
CREATE TABLE IF NOT EXISTS resource_health (
    id VARCHAR(36) PRIMARY KEY,
    health_run_id VARCHAR(36),
    timestamp DATETIME NOT NULL,
    service VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    status ENUM('HEALTHY', 'DEGRADED', 'UNHEALTHY', 'UNKNOWN', 'INITIALIZING', 'MAINTENANCE', 'INACTIVE') NOT NULL,
    status_reason TEXT,
    metrics JSON,
    events JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_health_run (health_run_id),
    INDEX idx_service (service),
    INDEX idx_status (status),
    INDEX idx_resource_id (resource_id),
    FOREIGN KEY (health_run_id) REFERENCES health_check_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- Compliance Checker Tables
-- ============================================

-- Table for compliance check runs
CREATE TABLE IF NOT EXISTS compliance_check_runs (
    id VARCHAR(36) PRIMARY KEY,
    check_time DATETIME NOT NULL,
    overall_score INT DEFAULT 100,
    pillar_scores JSON,
    total_findings INT DEFAULT 0,
    tagging_compliance_rate FLOAT DEFAULT 0.0,
    ai_recommendations TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_check_time (check_time),
    INDEX idx_overall_score (overall_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for individual compliance findings
CREATE TABLE IF NOT EXISTS compliance_findings (
    id VARCHAR(36) PRIMARY KEY,
    compliance_run_id VARCHAR(36),
    timestamp DATETIME NOT NULL,
    finding_type VARCHAR(100) NOT NULL,
    severity ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') NOT NULL,
    pillar VARCHAR(50),
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    recommendation TEXT,
    compliance_framework VARCHAR(100),
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_compliance_run (compliance_run_id),
    INDEX idx_severity (severity),
    INDEX idx_pillar (pillar),
    INDEX idx_finding_type (finding_type),
    INDEX idx_resolved (resolved),
    FOREIGN KEY (compliance_run_id) REFERENCES compliance_check_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- Service Quota Tables
-- ============================================

-- Table for quota check runs
CREATE TABLE IF NOT EXISTS quota_check_runs (
    id VARCHAR(36) PRIMARY KEY,
    check_time DATETIME NOT NULL,
    quotas_checked INT DEFAULT 0,
    critical_alerts INT DEFAULT 0,
    warning_alerts INT DEFAULT 0,
    ai_recommendations TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_check_time (check_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for individual quota status
CREATE TABLE IF NOT EXISTS quota_status (
    id VARCHAR(36) PRIMARY KEY,
    quota_run_id VARCHAR(36),
    timestamp DATETIME NOT NULL,
    service_code VARCHAR(100) NOT NULL,
    quota_code VARCHAR(100),
    quota_name VARCHAR(255) NOT NULL,
    quota_value FLOAT NOT NULL,
    current_usage FLOAT DEFAULT 0,
    usage_percentage FLOAT DEFAULT 0,
    unit VARCHAR(50) DEFAULT 'None',
    adjustable BOOLEAN DEFAULT FALSE,
    alert_level ENUM('CRITICAL', 'WARNING', 'OK'),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_quota_run (quota_run_id),
    INDEX idx_service_code (service_code),
    INDEX idx_alert_level (alert_level),
    INDEX idx_usage_percentage (usage_percentage),
    FOREIGN KEY (quota_run_id) REFERENCES quota_check_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- Backup & DR Tables
-- ============================================

-- Table for DR readiness check runs
CREATE TABLE IF NOT EXISTS dr_readiness_runs (
    id VARCHAR(36) PRIMARY KEY,
    check_time DATETIME NOT NULL,
    dr_score INT DEFAULT 100,
    readiness_level ENUM('EXCELLENT', 'GOOD', 'FAIR', 'POOR', 'CRITICAL') NOT NULL,
    total_findings INT DEFAULT 0,
    rds_snapshots_count INT DEFAULT 0,
    s3_buckets_with_versioning INT DEFAULT 0,
    cross_region_replications INT DEFAULT 0,
    ai_recommendations TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_check_time (check_time),
    INDEX idx_dr_score (dr_score),
    INDEX idx_readiness_level (readiness_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for backup status records
CREATE TABLE IF NOT EXISTS backup_status (
    id VARCHAR(36) PRIMARY KEY,
    dr_run_id VARCHAR(36),
    timestamp DATETIME NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_name VARCHAR(255),
    backup_type VARCHAR(50),
    status VARCHAR(50) NOT NULL,
    created DATETIME,
    age_days INT DEFAULT 0,
    size_gb FLOAT DEFAULT 0,
    encrypted BOOLEAN DEFAULT FALSE,
    cross_region BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_dr_run (dr_run_id),
    INDEX idx_resource_type (resource_type),
    INDEX idx_status (status),
    INDEX idx_age_days (age_days),
    FOREIGN KEY (dr_run_id) REFERENCES dr_readiness_runs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- Unified Scan Results Table
-- ============================================

-- Table for storing any type of scan result (for quick access)
CREATE TABLE IF NOT EXISTS scan_results (
    id VARCHAR(36) PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    scan_type ENUM('security', 'performance', 'health', 'compliance', 'quota', 'backup') NOT NULL,
    score INT DEFAULT 100,
    total_findings INT DEFAULT 0,
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    findings_json LONGTEXT,
    ai_recommendations TEXT,
    duration_seconds FLOAT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_scan_type (scan_type),
    INDEX idx_score (score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
