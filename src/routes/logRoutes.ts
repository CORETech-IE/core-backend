/**
 * 🚨 CORE-BACKEND: Nuclear Log Ingestion Routes
 * 
 * Multi-tenant log processing endpoints with comprehensive compliance
 * Single responsibility: Log ingestion ONLY
 * 
 * Classification: CONFIDENTIAL (log processing routes)
 * Retention: 7 years (operational requirement)
 * Review Date: Every 3 months (critical component)
 */

import express from 'express';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { emitLog, logHealthCheck } from '../controllers/logController';
import { authenticateRequest as authenticateJWT } from '../middlewares/authentication';
import logger from '../utils/logger';
import nuclearAuditLogger from '../middlewares/auditLogger';

const router = express.Router();

/**
 * Rate limiting for log ingestion endpoints
 * Balanced between throughput and abuse prevention
 */

// High-volume rate limiting for log ingestion
const logIngestionLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 1000, // 1000 log entries per minute per IP (high volume)
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Log ingestion rate limit exceeded',
    retry_after: '1 minute',
    note: 'High volume log ingestion detected'
  },
  handler: (req: Request, res: Response) => {
    const correlationId = (req as any).correlationId || 'unknown';
    const tenantName = req.body?.tenant_name || 'unknown';
    
    logger.warn('🚫 Log ingestion rate limit exceeded', {
      classification: 'HIGH',
      audit_event: 'LOG_INGESTION_RATE_LIMIT_EXCEEDED',
      tenant_name: tenantName,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      correlation_id: correlationId,
      security_violation: 'HIGH_VOLUME_ABUSE_PROTECTION'
    });
    
    nuclearAuditLogger.logEvent(
      'RATE_LIMIT_EXCEEDED' as any,
      'Log ingestion rate limit exceeded',
      'FAILURE',
      {
        resource_type: 'log_ingestion_endpoint',
        tenant_name: tenantName,
        source_ip: req.ip,
        correlation_id: correlationId,
        metadata: {
          endpoint: '/emit-log',
          limit_type: 'high_volume_protection',
          window_minutes: 1,
          max_requests: 1000
        }
      }
    );
    
    res.status(429).json({
      error: 'Log ingestion rate limit exceeded',
      retry_after: '1 minute',
      correlation_id: correlationId
    });
  }
});

// Moderate rate limiting for health checks
const healthCheckLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 health checks per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many health check requests',
    retry_after: '1 minute'
  }
});

/**
 * Input validation for log ingestion
 * Comprehensive validation with security controls
 */
const validateLogPayload = [
  // Tenant identification
  body('tenant_name')
    .isString()
    .isLength({ min: 1, max: 64 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Tenant name must be 1-64 characters, alphanumeric with underscore/dash only')
    .trim(),
  
  // Service identification
  body('service')
    .isString()
    .isLength({ min: 1, max: 64 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Service name must be 1-64 characters, alphanumeric with underscore/dash only')
    .trim(),
  
  // Log level
  body('level')
    .isIn(['debug', 'info', 'warn', 'error', 'critical'])
    .withMessage('Level must be one of: debug, info, warn, error, critical'),
  
  // Log message
  body('message')
    .isString()
    .isLength({ min: 1, max: 8192 })
    .withMessage('Message must be 1-8192 characters')
    .trim(),
  
  // Classification (mandatory for compliance)
  body('classification')
    .isIn(['public', 'internal', 'confidential', 'restricted'])
    .withMessage('Classification must be one of: public, internal, confidential, restricted'),
  
  // Retention period
  body('retention_period')
    .optional()
    .isInt({ min: 1, max: 3650 })
    .withMessage('Retention period must be 1-3650 days')
    .toInt(),
  
  // Timestamp (optional)
  body('timestamp')
    .optional()
    .isISO8601()
    .withMessage('Timestamp must be valid ISO 8601 format'),
  
  // Trace ID (optional)
  body('trace_id')
    .optional()
    .isUUID()
    .withMessage('Trace ID must be valid UUID format'),
  
  // Tags (optional)
  body('tags')
    .optional()
    .isArray({ max: 20 })
    .withMessage('Tags must be array with max 20 elements'),
  
  body('tags.*')
    .optional()
    .isString()
    .isLength({ max: 50 })
    .withMessage('Each tag must be string with max 50 characters')
    .trim(),
  
  // Context (optional)
  body('context')
    .optional()
    .isObject()
    .withMessage('Context must be object')
    .custom((value) => {
      try {
        const serialized = JSON.stringify(value);
        if (serialized.length > 32768) { // 32KB limit
          throw new Error('Context too large (max 32KB when serialized)');
        }
        return true;
      } catch (error) {
        throw new Error('Context must be valid JSON object');
      }
    })
];

/**
 * Validation result handler with security logging
 */
function handleLogValidationErrors(req: Request, res: Response, next: NextFunction): void {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const correlationId = (req as any).correlationId || 'unknown';
    const tenantName = req.body?.tenant_name || 'unknown';
    
    logger.warn('🚫 Log payload validation failed', {
      classification: 'HIGH',
      audit_event: 'LOG_PAYLOAD_VALIDATION_FAILED',
      tenant_name: tenantName,
      errors: errors.array(),
      endpoint: req.path,
      client_ip: req.ip,
      correlation_id: correlationId
    });
    
    nuclearAuditLogger.logEvent(
      'DATA_VALIDATION_FAILED' as any,
      'Log payload validation failed',
      'FAILURE',
      {
        resource_type: 'log_payload',
        tenant_name: tenantName,
        source_ip: req.ip,
        correlation_id: correlationId,
        metadata: {
          validation_errors: errors.array(),
          endpoint: req.path,
          security_impact: 'MALFORMED_DATA_ATTEMPT'
        }
      }
    );
    
    res.status(400).json({
      error: 'Invalid log payload',
      details: errors.array().map(err => ({
        field: err.type === 'field' ? err.path : 'unknown',
        message: err.msg
      })),
      correlation_id: correlationId
    });
    return;
  }
  
  next();
}

/**
 * Security headers for log ingestion endpoints
 */
function addLogSecurityHeaders(req: Request, res: Response, next: NextFunction): void {
  // Cache control for log responses
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Indicate this is a log processing endpoint
  res.setHeader('X-Log-Endpoint', 'true');
  res.setHeader('X-Service-Type', 'log-ingestion');
  
  next();
}

/**
 * Request logging for log ingestion endpoints
 */
function logIngestionRequest(endpoint: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const correlationId = (req as any).correlationId || 'unknown';
    const tenantName = req.body?.tenant_name || 'unknown';
    
    logger.info(`📥 Log ingestion request: ${endpoint}`, {
      classification: 'INTERNAL',
      audit_event: 'LOG_INGESTION_REQUEST_RECEIVED',
      endpoint,
      method: req.method,
      tenant_name: tenantName,
      client_ip: req.ip,
      user_agent: req.headers['user-agent'],
      content_length: req.headers['content-length'],
      correlation_id: correlationId
    });
    
    next();
  };
}

/**
 * Authentication verification for log endpoints
 * Ensures only authenticated services can ingest logs
 */
function verifyLogIngestionAuth(req: Request, res: Response, next: NextFunction): void {
  const user = (req as any).user;
  const correlationId = (req as any).correlationId || 'unknown';
  
  if (!user) {
    logger.error('💥 No user context in authenticated request', {
      classification: 'CRITICAL',
      audit_event: 'LOG_INGESTION_AUTH_CONTEXT_MISSING',
      correlation_id: correlationId
    });
    
    res.status(500).json({
      error: 'Authentication context missing',
      correlation_id: correlationId
    });
    return;
  }
  
  // Log successful authentication for audit
  nuclearAuditLogger.logEvent(
    'ACCESS_GRANTED' as any,
    'Log ingestion access granted',
    'SUCCESS',
    {
      resource_type: 'log_ingestion_endpoint',
      user_id: user.username,
      source_ip: req.ip,
      correlation_id: correlationId,
      metadata: {
        user_role: user.role,
        tenant_id: user.tenant_id,
        endpoint: req.originalUrl,
        authentication_method: 'jwt'
      }
    }
  );
  
  next();
}

/**
 * ROUTES DEFINITION
 * Log ingestion endpoints with comprehensive security
 */

// POST /api/emit-log - Main log ingestion endpoint
router.post('/emit-log',
  addLogSecurityHeaders,
  logIngestionRequest('emit-log'),
  logIngestionLimiter,
  authenticateJWT,
  verifyLogIngestionAuth,
  validateLogPayload,
  handleLogValidationErrors,
  emitLog
);

// GET /api/logs/health - Log service health check
router.get('/logs/health',
  addLogSecurityHeaders,
  logIngestionRequest('logs-health'),
  healthCheckLimiter,
  logHealthCheck
);

// GET /api/health - General API health (alias)
router.get('/health', (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  const healthStatus = {
    status: 'healthy',
    service: 'log-ingestion-api',
    timestamp: new Date().toISOString(),
    endpoints: {
      emit_log: 'available',
      logs_health: 'available'
    },
    rate_limits: {
      log_ingestion: '1000 requests per minute',
      health_checks: '60 requests per minute'
    },
    security: {
      authentication: 'required',
      input_validation: 'active',
      rate_limiting: 'active',
      audit_logging: 'active'
    },
    compliance: {
      iso27001: 'active',
      gdpr: 'compliant',
      classification_enforcement: 'active'
    },
    correlation_id: correlationId
  };
  
  logger.info('🏥 API health check', {
    classification: 'INTERNAL',
    audit_event: 'API_HEALTH_CHECK',
    correlation_id: correlationId
  });
  
  res.status(200).json(healthStatus);
});

// OPTIONS support for CORS preflight
router.options('*', (req: Request, res: Response) => {
  res.status(200).end();
});

// 404 handler for log routes
router.use('*', (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  logger.warn('🚫 Log API endpoint not found', {
    classification: 'INTERNAL',
    audit_event: 'LOG_API_ENDPOINT_NOT_FOUND',
    method: req.method,
    path: req.path,
    client_ip: req.ip,
    correlation_id: correlationId
  });
  
  res.status(404).json({
    error: 'Log API endpoint not found',
    available_endpoints: [
      'POST /api/emit-log',
      'GET /api/logs/health',
      'GET /api/health'
    ],
    correlation_id: correlationId
  });
});

export default router;