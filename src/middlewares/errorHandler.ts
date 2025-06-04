/**
 * 🚨 CORE-BACKEND: Nuclear Error Handler
 * 
 * Comprehensive error handling with security and compliance logging
 * Implements defense-in-depth error management strategy
 * 
 * Classification: CONFIDENTIAL (error handling logic)
 * Retention: 7 years (security requirement)
 * Review Date: Every 3 months (critical security component)
 */

import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

/**
 * Error categories for classification and response handling
 */
enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION', 
  AUTHORIZATION = 'AUTHORIZATION',
  NOT_FOUND = 'NOT_FOUND',
  RATE_LIMIT = 'RATE_LIMIT',
  DATABASE = 'DATABASE',
  EXTERNAL_SERVICE = 'EXTERNAL_SERVICE',
  SYSTEM = 'SYSTEM',
  UNKNOWN = 'UNKNOWN'
}

/**
 * Error severity levels for compliance and monitoring
 */
enum ErrorSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM', 
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

/**
 * Enhanced error interface with security context
 */
interface EnhancedError extends Error {
  statusCode?: number;
  category?: ErrorCategory;
  severity?: ErrorSeverity;
  correlationId?: string;
  userContext?: {
    user_id?: string;
    ip_address?: string;
    user_agent?: string;
  };
  securityContext?: {
    is_attack?: boolean;
    attack_type?: string;
    blocked?: boolean;
  };
}

/**
 * Categorize error based on properties and context
 */
function categorizeError(error: any, req: Request): {
  category: ErrorCategory;
  severity: ErrorSeverity;
  statusCode: number;
  securityRelevant: boolean;
} {
  // Handle known error types
  if (error.name === 'ValidationError' || error.statusCode === 400) {
    return {
      category: ErrorCategory.VALIDATION,
      severity: ErrorSeverity.MEDIUM,
      statusCode: 400,
      securityRelevant: true
    };
  }
  
  if (error.statusCode === 401 || error.name === 'UnauthorizedError') {
    return {
      category: ErrorCategory.AUTHENTICATION,
      severity: ErrorSeverity.HIGH,
      statusCode: 401,
      securityRelevant: true
    };
  }
  
  if (error.statusCode === 403 || error.name === 'ForbiddenError') {
    return {
      category: ErrorCategory.AUTHORIZATION,
      severity: ErrorSeverity.HIGH,
      statusCode: 403,
      securityRelevant: true
    };
  }
  
  if (error.statusCode === 404 || error.name === 'NotFoundError') {
    return {
      category: ErrorCategory.NOT_FOUND,
      severity: ErrorSeverity.LOW,
      statusCode: 404,
      securityRelevant: false
    };
  }
  
  if (error.statusCode === 429 || error.name === 'TooManyRequestsError') {
    return {
      category: ErrorCategory.RATE_LIMIT,
      severity: ErrorSeverity.HIGH,
      statusCode: 429,
      securityRelevant: true
    };
  }
  
  // Database errors
  if (error.code && (error.code.startsWith('23') || error.code.startsWith('42'))) {
    return {
      category: ErrorCategory.DATABASE,
      severity: ErrorSeverity.HIGH,
      statusCode: 500,
      securityRelevant: true
    };
  }
  
  // Network/timeout errors
  if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
    return {
      category: ErrorCategory.EXTERNAL_SERVICE,
      severity: ErrorSeverity.MEDIUM,
      statusCode: 503,
      securityRelevant: false
    };
  }
  
  // System errors (5xx range)
  if (error.statusCode >= 500) {
    return {
      category: ErrorCategory.SYSTEM,
      severity: ErrorSeverity.CRITICAL,
      statusCode: error.statusCode,
      securityRelevant: false
    };
  }
  
  // Unknown errors
  return {
    category: ErrorCategory.UNKNOWN,
    severity: ErrorSeverity.CRITICAL,
    statusCode: 500,
    securityRelevant: true
  };
}

/**
 * Extract security context from request and error
 */
function extractSecurityContext(error: any, req: Request): {
  userContext: any;
  securityContext: any;
  requestContext: any;
} {
  const userContext = {
    user_id: (req as any).user?.username || 'anonymous',
    ip_address: req.ip || 'unknown',
    user_agent: req.headers['user-agent'] || 'unknown',
    tenant_name: (req as any).tenantName || 'unknown'
  };
  
  // Detect potential security issues
  const securityContext: {
    is_attack: boolean;
    attack_type: string | null;
    blocked: boolean;
  } = {
    is_attack: false,
    attack_type: null,
    blocked: false
  };
  
  // SQL injection patterns
  if (error.message && /(\bSELECT\b|\bUNION\b|\bDROP\b)/i.test(error.message)) {
    securityContext.is_attack = true;
    securityContext.attack_type = 'SQL_INJECTION_ATTEMPT';
  }
  
  // XSS patterns
  if (error.message && /<script|javascript:|on\w+=/i.test(error.message)) {
    securityContext.is_attack = true;
    securityContext.attack_type = 'XSS_ATTEMPT';
  }
  
  // Path traversal patterns
  if (error.message && /\.\.\/|\.\.\\/.test(error.message)) {
    securityContext.is_attack = true;
    securityContext.attack_type = 'PATH_TRAVERSAL_ATTEMPT';
  }
  
  const requestContext = {
    method: req.method,
    path: req.originalUrl || req.url,
    query_params: Object.keys(req.query).length > 0 ? req.query : undefined,
    content_length: req.headers['content-length'],
    referer: req.headers.referer
  };
  
  return { userContext, securityContext, requestContext };
}

/**
 * Sanitize error message for client response
 * Prevents information leakage while maintaining usability
 */
function sanitizeErrorMessage(error: any, category: ErrorCategory, isProduction: boolean): string {
  // In production, don't leak internal details
  if (isProduction) {
    switch (category) {
      case ErrorCategory.VALIDATION:
        return 'Invalid request data';
      case ErrorCategory.AUTHENTICATION:
        return 'Authentication required';
      case ErrorCategory.AUTHORIZATION:
        return 'Access denied';
      case ErrorCategory.NOT_FOUND:
        return 'Resource not found';
      case ErrorCategory.RATE_LIMIT:
        return 'Too many requests';
      case ErrorCategory.DATABASE:
        return 'Data processing error';
      case ErrorCategory.EXTERNAL_SERVICE:
        return 'Service temporarily unavailable';
      default:
        return 'Internal server error';
    }
  }
  
  // In development, provide more details
  return error.message || 'Unknown error occurred';
}

/**
 * Nuclear error handler middleware
 * Implements comprehensive error processing with security and compliance
 */
export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const startTime = Date.now();
  const correlationId = (req as any).correlationId || 'unknown';
  const isProduction = process.env.NODE_ENV === 'production';
  
  try {
    // Categorize error
    const { category, severity, statusCode, securityRelevant } = categorizeError(err, req);
    
    // Extract context
    const { userContext, securityContext, requestContext } = extractSecurityContext(err, req);
    
    // Determine log classification based on severity
    const logClassification = severity === ErrorSeverity.CRITICAL ? 'CRITICAL' :
                             severity === ErrorSeverity.HIGH ? 'HIGH' :
                             securityRelevant ? 'HIGH' : 'INTERNAL';
    
    // Log error with comprehensive context
    logger.error('💥 Request error occurred', {
      classification: logClassification,
      audit_event: 'REQUEST_ERROR',
      correlation_id: correlationId,
      
      // Error details
      error: {
        category,
        severity,
        message: err.message,
        name: err.name,
        code: err.code,
        stack: isProduction ? undefined : err.stack // Don't log stack in production
      },
      
      // Security context
      security: securityContext,
      
      // User and request context
      user: userContext,
      request: requestContext,
      
      // Response context
      response: {
        status_code: statusCode,
        processing_time_ms: Date.now() - startTime
      }
    });
    
    // Enhanced logging for security events
    if (securityContext.is_attack) {
      logger.security('🚨 Potential security attack detected', {
        correlation_id: correlationId,
        attack_type: securityContext.attack_type,
        user_context: userContext,
        request_context: requestContext,
        error_message: err.message
      });
    }
    
    // Enhanced logging for critical errors
    if (severity === ErrorSeverity.CRITICAL) {
      logger.audit('CRITICAL_ERROR', 'Critical system error occurred', {
        correlation_id: correlationId,
        category,
        error_message: err.message,
        user_context: userContext,
        system_impact: 'HIGH'
      });
    }
    
    // Prepare client response
    const clientMessage = sanitizeErrorMessage(err, category, isProduction);
    
    // Build response object
    const errorResponse: any = {
      status: 'error',
      message: clientMessage,
      correlation_id: correlationId,
      timestamp: new Date().toISOString()
    };
    
    // Add additional context in development
    if (!isProduction) {
      errorResponse.details = {
        category,
        original_message: err.message,
        path: req.originalUrl
      };
    }
    
    // Add retry guidance for temporary errors
    if (category === ErrorCategory.EXTERNAL_SERVICE || category === ErrorCategory.DATABASE) {
      errorResponse.retry_after = '30 seconds';
    }
    
    // Add rate limit info
    if (category === ErrorCategory.RATE_LIMIT) {
      errorResponse.retry_after = req.headers['retry-after'] || '60 seconds';
    }
    
    // Send response
    res.status(statusCode).json(errorResponse);
    
  } catch (handlerError) {
    // Error in error handler - log and fail gracefully
    logger.error('💥 CRITICAL: Error handler failure', {
      classification: 'CRITICAL',
      audit_event: 'ERROR_HANDLER_FAILURE',
      correlation_id: correlationId,
      original_error: err.message,
      handler_error: handlerError instanceof Error ? handlerError.message : String(handlerError),
      stack: handlerError instanceof Error ? handlerError.stack : undefined
    });
    
    // Last resort response
    res.status(500).json({
      status: 'error',
      message: 'Critical system error',
      correlation_id: correlationId,
      timestamp: new Date().toISOString()
    });
  }
};

/**
 * 404 Not Found handler
 * Handles requests to non-existent endpoints
 */
export const notFoundHandler = (req: Request, res: Response): void => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  logger.warn('🚫 Endpoint not found', {
    classification: 'INTERNAL',
    audit_event: 'ENDPOINT_NOT_FOUND',
    correlation_id: correlationId,
    method: req.method,
    path: req.originalUrl,
    client_ip: req.ip,
    user_agent: req.headers['user-agent']
  });
  
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found',
    correlation_id: correlationId,
    timestamp: new Date().toISOString(),
    available_endpoints: [
      'GET /health',
      'POST /auth/login',
      'POST /api/emit-log'
    ]
  });
};

/**
 * Async error wrapper for route handlers
 * Catches async errors and passes to error handler
 */
export const asyncErrorHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};