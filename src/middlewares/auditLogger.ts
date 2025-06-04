/**
 * 🚨 CORE-BACKEND: Nuclear Audit Logger Middleware
 * 
 * Comprehensive audit trail middleware for compliance
 * Implements ISO 27001 A.12.4.1 comprehensive event logging
 * 
 * Classification: CONFIDENTIAL (audit infrastructure)
 * Retention: 7 years (regulatory requirement)
 * Review Date: Every 3 months (critical compliance component)
 */

import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import logger from '../utils/logger';

/**
 * Audit event types for compliance categorization
 */
export enum AuditEventType {
  // Authentication events
  AUTH_SUCCESS = 'AUTH_SUCCESS',
  AUTH_FAILURE = 'AUTH_FAILURE',
  AUTH_LOGOUT = 'AUTH_LOGOUT',
  TOKEN_GENERATED = 'TOKEN_GENERATED',
  TOKEN_VALIDATED = 'TOKEN_VALIDATED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  
  // Authorization events
  ACCESS_GRANTED = 'ACCESS_GRANTED',
  ACCESS_DENIED = 'ACCESS_DENIED',
  PERMISSION_ESCALATION = 'PERMISSION_ESCALATION',
  
  // Data processing events
  DATA_CREATED = 'DATA_CREATED',
  DATA_ACCESSED = 'DATA_ACCESSED',
  DATA_MODIFIED = 'DATA_MODIFIED',
  DATA_DELETED = 'DATA_DELETED',
  DATA_EXPORTED = 'DATA_EXPORTED',
  
  // Log processing events
  LOG_INGESTED = 'LOG_INGESTED',
  LOG_VALIDATED = 'LOG_VALIDATED',
  LOG_CLASSIFIED = 'LOG_CLASSIFIED',
  LOG_RETENTION_APPLIED = 'LOG_RETENTION_APPLIED',
  
  // System events
  SERVICE_STARTED = 'SERVICE_STARTED',
  SERVICE_STOPPED = 'SERVICE_STOPPED',
  CONFIG_CHANGED = 'CONFIG_CHANGED',
  ERROR_OCCURRED = 'ERROR_OCCURRED',
  
  // Security events
  SECURITY_VIOLATION = 'SECURITY_VIOLATION',
  ATTACK_DETECTED = 'ATTACK_DETECTED',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  
  // Compliance events
  GDPR_REQUEST = 'GDPR_REQUEST',
  DATA_RETENTION_CLEANUP = 'DATA_RETENTION_CLEANUP',
  COMPLIANCE_VALIDATION = 'COMPLIANCE_VALIDATION',
  AUDIT_LOG_ACCESS = 'AUDIT_LOG_ACCESS'
}

/**
 * Audit log entry interface
 * Structured format for comprehensive audit trails
 */
interface AuditLogEntry {
  // Core audit fields (ISO 27001 A.12.4.1)
  event_type: AuditEventType;
  timestamp: string;
  correlation_id: string;
  
  // Subject (who)
  user_id?: string;
  user_role?: string;
  service_account?: string;
  
  // Object (what)
  resource_type?: string;
  resource_id?: string;
  tenant_name?: string;
  
  // Action (what happened)
  action: string;
  outcome: 'SUCCESS' | 'FAILURE' | 'PARTIAL';
  
  // Context (how/where/when)
  source_ip?: string;
  user_agent?: string;
  session_id?: string;
  request_id?: string;
  
  // Technical details
  method?: string;
  endpoint?: string;
  status_code?: number;
  duration_ms?: number;
  
  // Security context
  classification?: string;
  risk_score?: number;
  threat_indicators?: string[];
  
  // Compliance context
  data_categories?: string[];
  legal_basis?: string;
  retention_period?: number;
  
  // Additional metadata
  metadata?: Record<string, any>;
}

/**
 * Risk scoring for audit events
 * Helps prioritize security investigations
 */
function calculateRiskScore(
  eventType: AuditEventType,
  outcome: string,
  context: any
): number {
  let score = 0;
  
  // Base score by event type
  switch (eventType) {
    case AuditEventType.AUTH_FAILURE:
    case AuditEventType.ACCESS_DENIED:
      score += 3;
      break;
    case AuditEventType.SECURITY_VIOLATION:
    case AuditEventType.ATTACK_DETECTED:
      score += 8;
      break;
    case AuditEventType.DATA_DELETED:
    case AuditEventType.DATA_EXPORTED:
      score += 5;
      break;
    case AuditEventType.PERMISSION_ESCALATION:
      score += 6;
      break;
    default:
      score += 1;
  }
  
  // Failure increases risk
  if (outcome === 'FAILURE') {
    score += 2;
  }
  
  // Multiple failures from same IP
  if (context.repeated_failures > 3) {
    score += 3;
  }
  
  // Suspicious patterns
  if (context.off_hours) {
    score += 1;
  }
  
  if (context.unusual_location) {
    score += 2;
  }
  
  return Math.min(score, 10); // Cap at 10
}

/**
 * Detect threat indicators from request context
 */
function detectThreatIndicators(req: Request, eventType: AuditEventType): string[] {
  const indicators: string[] = [];
  
  // SQL injection patterns in query/body
  const sqlPatterns = /(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)/i;
  const requestData = JSON.stringify({ query: req.query, body: req.body });
  
  if (sqlPatterns.test(requestData)) {
    indicators.push('SQL_INJECTION_PATTERN');
  }
  
  // XSS patterns
  const xssPatterns = /<script|javascript:|on\w+=/i;
  if (xssPatterns.test(requestData)) {
    indicators.push('XSS_PATTERN');
  }
  
  // Path traversal
  const pathTraversalPatterns = /\.\.\/|\.\.\\|%2e%2e/i;
  if (pathTraversalPatterns.test(req.originalUrl || '')) {
    indicators.push('PATH_TRAVERSAL_PATTERN');
  }
  
  // Unusual user agents
  const userAgent = req.headers['user-agent'] || '';
  if (userAgent.includes('sqlmap') || userAgent.includes('nmap') || userAgent.includes('nikto')) {
    indicators.push('ATTACK_TOOL_USER_AGENT');
  }
  
  // Rapid requests (if we tracked this)
  if ((req as any).rapidRequests > 10) {
    indicators.push('RAPID_REQUESTS');
  }
  
  // Authentication without proper headers
  if (eventType === AuditEventType.AUTH_FAILURE && !req.headers.authorization) {
    indicators.push('AUTH_WITHOUT_HEADER');
  }
  
  return indicators;
}

/**
 * Audit logger class for comprehensive event logging
 */
class NuclearAuditLogger {
  
  /**
   * Log audit event with comprehensive context
   */
  logEvent(
    eventType: AuditEventType,
    action: string,
    outcome: 'SUCCESS' | 'FAILURE' | 'PARTIAL',
    context: Partial<AuditLogEntry> = {}
  ): void {
    
    const timestamp = new Date().toISOString();
    const correlationId = context.correlation_id || uuidv4();
    
    // Calculate risk score
    const riskScore = calculateRiskScore(eventType, outcome, context);
    
    // Build comprehensive audit entry
    const auditEntry: AuditLogEntry = {
      event_type: eventType,
      timestamp,
      correlation_id: correlationId,
      action,
      outcome,
      risk_score: riskScore,
      ...context
    };
    
    // Determine log classification based on event type and risk
    let classification: 'PUBLIC' | 'INTERNAL' | 'HIGH' | 'CONFIDENTIAL' | 'CRITICAL' = 'INTERNAL';
    if (riskScore >= 7) {
      classification = 'CRITICAL';
    } else if (riskScore >= 4 || eventType.includes('SECURITY') || eventType.includes('AUTH')) {
      classification = 'HIGH';
    } else if (eventType.includes('DATA')) {
      classification = 'CONFIDENTIAL';
    }
    
    // Build comprehensive audit entry (without correlation_id and classification to avoid conflicts)
    const { correlation_id: _, classification: __, ...auditEntryWithoutConflicts } = auditEntry;
    
    // Log with appropriate classification
    logger.audit(eventType, `${action} - ${outcome}`, {
      classification,
      correlation_id: correlationId,
      risk_score: riskScore,
      ...auditEntryWithoutConflicts
    });
    
    // Enhanced logging for high-risk events
    if (riskScore >= 6) {
      logger.security('🚨 High-risk audit event detected', {
        correlation_id: correlationId,
        event_type: eventType,
        risk_score: riskScore,
        action,
        outcome,
        threat_indicators: context.threat_indicators
      });
    }
  }
  
  /**
   * Log authentication event
   */
  logAuthEvent(
    success: boolean,
    username: string,
    req: Request,
    additionalContext: any = {}
  ): void {
    const eventType = success ? AuditEventType.AUTH_SUCCESS : AuditEventType.AUTH_FAILURE;
    const outcome = success ? 'SUCCESS' : 'FAILURE';
    
    this.logEvent(eventType, `User authentication for ${username}`, outcome, {
      correlation_id: (req as any).correlationId,
      user_id: username,
      source_ip: req.ip,
      user_agent: req.headers['user-agent'],
      method: req.method,
      endpoint: req.originalUrl,
      threat_indicators: detectThreatIndicators(req, eventType),
      ...additionalContext
    });
  }
  
  /**
   * Log data access event
   */
  logDataAccess(
    resourceType: string,
    resourceId: string,
    action: string,
    req: Request,
    success: boolean = true,
    additionalContext: any = {}
  ): void {
    const outcome = success ? 'SUCCESS' : 'FAILURE';
    
    this.logEvent(AuditEventType.DATA_ACCESSED, `${action} ${resourceType}`, outcome, {
      correlation_id: (req as any).correlationId,
      resource_type: resourceType,
      resource_id: resourceId,
      user_id: (req as any).user?.username,
      tenant_name: (req as any).tenantName,
      source_ip: req.ip,
      method: req.method,
      endpoint: req.originalUrl,
      ...additionalContext
    });
  }
  
  /**
   * Log log ingestion event (meta!)
   */
  logLogIngestion(
    tenantName: string,
    classification: string,
    req: Request,
    success: boolean = true,
    additionalContext: any = {}
  ): void {
    const outcome = success ? 'SUCCESS' : 'FAILURE';
    
    this.logEvent(AuditEventType.LOG_INGESTED, `Log ingestion for ${tenantName}`, outcome, {
      correlation_id: (req as any).correlationId,
      tenant_name: tenantName,
      classification,
      user_id: (req as any).user?.username,
      source_ip: req.ip,
      method: req.method,
      endpoint: req.originalUrl,
      data_categories: ['log_data'],
      legal_basis: 'legitimate_interest',
      ...additionalContext
    });
  }
}

// Create singleton audit logger instance
const nuclearAuditLogger = new NuclearAuditLogger();

/**
 * Express middleware for automatic request auditing
 * Logs all requests with comprehensive context
 */
export const auditLoggerMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();
  const correlationId = (req as any).correlationId || uuidv4();
  
  // Store correlation ID if not already present
  (req as any).correlationId = correlationId;
  
  // Log request start
  nuclearAuditLogger.logEvent(
    AuditEventType.DATA_ACCESSED,
    `HTTP request to ${req.method} ${req.originalUrl}`,
    'SUCCESS',
    {
      correlation_id: correlationId,
      method: req.method,
      endpoint: req.originalUrl,
      source_ip: req.ip,
      user_agent: req.headers['user-agent'],
      user_id: (req as any).user?.username || 'anonymous',
      tenant_name: (req as any).tenantName,
      threat_indicators: detectThreatIndicators(req, AuditEventType.DATA_ACCESSED)
    }
  );
  
  // Capture response
  const originalEnd = res.end.bind(res);
  (res as any).end = (...args: any[]) => {
    const duration = Date.now() - startTime;
    
    // Log request completion
    nuclearAuditLogger.logEvent(
      AuditEventType.DATA_ACCESSED,
      `HTTP request completed ${req.method} ${req.originalUrl}`,
      res.statusCode < 400 ? 'SUCCESS' : 'FAILURE',
      {
        correlation_id: correlationId,
        method: req.method,
        endpoint: req.originalUrl,
        status_code: res.statusCode,
        duration_ms: duration,
        source_ip: req.ip,
        user_id: (req as any).user?.username || 'anonymous'
      }
    );
    
    return originalEnd(...args);
  };
  
  next();
};

// Export instance and default
export { nuclearAuditLogger };
export default nuclearAuditLogger;