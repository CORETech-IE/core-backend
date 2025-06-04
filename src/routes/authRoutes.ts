/**
 * 🚨 CORE-BACKEND: Nuclear Authentication Routes
 * 
 * Secure authentication endpoints with comprehensive security controls
 * Compatible with Oracle PL/SQL, JavaScript, Python clients
 * 
 * Classification: CONFIDENTIAL (authentication routes)
 * Retention: 7 years (security requirement)
 * Review Date: Every 3 months (critical security component)
 */

import express from 'express';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';
import { login, validateToken, refreshToken } from '../controllers/authController';
import logger from '../utils/logger';

const router = express.Router();

/**
 * Enhanced rate limiting for authentication endpoints
 * Implements progressive rate limiting based on endpoint sensitivity
 */

// Strict rate limiting for login (prevent brute force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 login attempts per 15 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many login attempts',
    retry_after: '15 minutes',
    security_note: 'Account protection active'
  },
  handler: (req: Request, res: Response) => {
    const correlationId = (req as any).correlationId || 'unknown';
    
    logger.warn('🚫 Login rate limit exceeded', {
      classification: 'HIGH',
      audit_event: 'LOGIN_RATE_LIMIT_EXCEEDED',
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      correlation_id: correlationId,
      security_violation: 'BRUTE_FORCE_PROTECTION'
    });
    
    res.status(429).json({
      error: 'Too many login attempts',
      retry_after: '15 minutes',
      correlation_id: correlationId
    });
  },
  skip: (req: Request) => {
    // Skip rate limiting for health checks or internal requests
    const userAgent = req.headers['user-agent'] || '';
    return userAgent.includes('health-check') || userAgent.includes('monitoring');
  }
});

// Moderate rate limiting for token validation
const validateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 validation attempts per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many validation requests',
    retry_after: '1 minute'
  }
});

// Moderate rate limiting for token refresh
const refreshLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // 10 refresh attempts per 5 minutes per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many refresh requests',
    retry_after: '5 minutes'
  }
});

/**
 * Input validation middleware for authentication endpoints
 * Implements comprehensive input sanitization and validation
 */

// Login input validation
const validateLoginInput = [
  body('username')
    .isString()
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username must be 3-50 characters, alphanumeric with underscore/dash only')
    .trim()
    .escape(),
  
  body('password')
    .isString()
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be 8-128 characters')
    // Note: We don't escape password as it needs to be compared as-is
];

/**
 * Validation result handler
 * Processes validation errors with security logging
 */
function handleValidationErrors(req: Request, res: Response, next: NextFunction): void {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const correlationId = (req as any).correlationId || 'unknown';
    
    logger.warn('🚫 Input validation failed', {
      classification: 'HIGH',
      audit_event: 'INPUT_VALIDATION_FAILED',
      errors: errors.array(),
      endpoint: req.path,
      client_ip: req.ip,
      correlation_id: correlationId
    });
    
    res.status(400).json({
      error: 'Invalid input',
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
 * Security headers middleware for authentication endpoints
 * Adds extra security headers for auth-specific protection
 */
function addAuthSecurityHeaders(req: Request, res: Response, next: NextFunction): void {
  // Prevent caching of authentication responses
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  
  // Add authentication-specific security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Indicate this is an authentication endpoint
  res.setHeader('X-Auth-Endpoint', 'true');
  
  next();
}

/**
 * Request logging middleware for authentication endpoints
 * Provides enhanced logging for security-sensitive operations
 */
function logAuthRequest(endpoint: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const correlationId = (req as any).correlationId || 'unknown';
    
    logger.info(`🔐 Auth request: ${endpoint}`, {
      classification: 'HIGH',
      audit_event: 'AUTH_REQUEST_RECEIVED',
      endpoint,
      method: req.method,
      client_ip: req.ip,
      user_agent: req.headers['user-agent'],
      content_length: req.headers['content-length'],
      correlation_id: correlationId
    });
    
    next();
  };
}

/**
 * ROUTES DEFINITION
 * All authentication endpoints with comprehensive security
 */

// POST /auth/login - User authentication
router.post('/login',
  addAuthSecurityHeaders,
  logAuthRequest('login'),
  loginLimiter,
  validateLoginInput,
  handleValidationErrors,
  login
);

// POST /auth/validate - Token validation
router.post('/validate',
  addAuthSecurityHeaders,
  logAuthRequest('validate'),
  validateLimiter,
  validateToken
);

// POST /auth/refresh - Token refresh
router.post('/refresh',
  addAuthSecurityHeaders,
  logAuthRequest('refresh'),
  refreshLimiter,
  refreshToken
);

// GET /auth/health - Authentication service health check
router.get('/health', (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  const healthStatus = {
    status: 'healthy',
    service: 'authentication',
    timestamp: new Date().toISOString(),
    endpoints: {
      login: 'available',
      validate: 'available',
      refresh: 'available'
    },
    rate_limits: {
      login: '5 requests per 15 minutes',
      validate: '60 requests per minute',
      refresh: '10 requests per 5 minutes'
    },
    security: {
      input_validation: 'active',
      rate_limiting: 'active',
      audit_logging: 'active'
    },
    correlation_id: correlationId
  };
  
  logger.info('🏥 Auth health check', {
    classification: 'INTERNAL',
    audit_event: 'AUTH_HEALTH_CHECK',
    correlation_id: correlationId
  });
  
  res.status(200).json(healthStatus);
});

// OPTIONS support for CORS preflight
router.options('*', (req: Request, res: Response) => {
  res.status(200).end();
});

// 404 handler for auth routes
router.use('*', (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  logger.warn('🚫 Auth endpoint not found', {
    classification: 'INTERNAL',
    audit_event: 'AUTH_ENDPOINT_NOT_FOUND',
    method: req.method,
    path: req.path,
    client_ip: req.ip,
    correlation_id: correlationId
  });
  
  res.status(404).json({
    error: 'Authentication endpoint not found',
    available_endpoints: [
      'POST /auth/login',
      'POST /auth/validate', 
      'POST /auth/refresh',
      'GET /auth/health'
    ],
    correlation_id: correlationId
  });
});

export default router;