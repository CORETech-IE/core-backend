/**
 * 🚨 CORE-BACKEND: Nuclear Authentication Middleware
 * 
 * Zero Trust Authentication Implementation
 * Compliance: Never Trust, Always Verify
 * 
 * Classification: CONFIDENTIAL (authentication logic)
 * Retention: 7 years (security requirement)
 * Review Date: Every 3 months
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import config from '../config/envConfig';
import logger from '../utils/logger';
import nuclearAuditLogger from './auditLogger';

/**
 * Extended Request interface with authenticated user
 */
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    tenant_name: string;
    roles: string[];
    permissions: string[];
    session_id: string;
    iat: number;
    exp: number;
  };
  correlation_id?: string;
}

/**
 * JWT Token payload interface
 */
interface JWTPayload {
  sub: string; // user id
  tenant_name: string;
  roles: string[];
  permissions: string[];
  session_id: string;
  iat: number;
  exp: number;
}

/**
 * Authentication error with security context
 */
export class AuthenticationError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly httpStatus: number = 401
  ) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

/**
 * Nuclear authentication middleware
 * Implements Zero Trust "Never Trust, Always Verify" principle
 */
export function authenticateRequest(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const startTime = Date.now();
  const correlationId = req.headers['x-correlation-id'] as string || generateCorrelationId();
  req.correlation_id = correlationId;
  
  try {
    // 🔍 STEP 1: Extract and validate token
    const token = extractToken(req);
    if (!token) {
      throw new AuthenticationError(
        'Authentication token required',
        'TOKEN_MISSING'
      );
    }
    
    // 🔐 STEP 2: Verify JWT signature and claims
    const payload = verifyToken(token);
    
    // 🛡️ STEP 3: Validate token claims
    validateTokenClaims(payload);
    
    // 👤 STEP 4: Attach user context to request
    req.user = {
      id: payload.sub,
      tenant_name: payload.tenant_name,
      roles: payload.roles,
      permissions: payload.permissions,
      session_id: payload.session_id,
      iat: payload.iat,
      exp: payload.exp
    };
    
    // 📊 STEP 5: Log successful authentication
    const duration = Date.now() - startTime;
    
    logger.info('🔐 Authentication successful', {
      classification: 'CONFIDENTIAL',
      audit_event: 'AUTHENTICATION_SUCCESS',
      user_id: payload.sub,
      tenant_name: payload.tenant_name,
      session_id: payload.session_id,
      correlation_id: correlationId,
      duration_ms: duration,
      ip_address: getClientIP(req),
      user_agent: req.headers['user-agent']
    });
    
    // Audit log for compliance
    nuclearAuditLogger.logEvent(
      'AUTH_SUCCESS' as any,
      'User successfully authenticated',
      'SUCCESS',
      {
        resource_type: 'authentication',
        resource_id: payload.sub,
        metadata: {
          tenant_name: payload.tenant_name,
          session_id: payload.session_id,
          correlation_id: correlationId,
          roles: payload.roles,
          ip_address: getClientIP(req),
          duration_ms: duration
        }
      }
    );
    
    next();
    
  } catch (error) {
    handleAuthenticationError(error, req, res, correlationId);
  }
}

/**
 * Extract Bearer token from Authorization header
 */
function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return null;
  }
  
  const matches = authHeader.match(/^Bearer\s+(.+)$/);
  return matches ? matches[1] : null;
}

/**
 * Verify JWT token signature and decode payload
 */
function verifyToken(token: string): JWTPayload {
  try {
    const decoded = jwt.verify(token, config.jwtSecret) as JWTPayload;
    return decoded;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new AuthenticationError(
        'Authentication token expired',
        'TOKEN_EXPIRED'
      );
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new AuthenticationError(
        'Invalid authentication token',
        'TOKEN_INVALID'
      );
    } else {
      throw new AuthenticationError(
        'Token verification failed',
        'TOKEN_VERIFICATION_FAILED'
      );
    }
  }
}

/**
 * Validate token claims for security requirements
 */
function validateTokenClaims(payload: JWTPayload): void {
  // Validate required claims
  if (!payload.sub) {
    throw new AuthenticationError(
      'Token missing user identifier',
      'TOKEN_MISSING_USER_ID'
    );
  }
  
  if (!payload.tenant_name) {
    throw new AuthenticationError(
      'Token missing tenant identifier',
      'TOKEN_MISSING_TENANT'
    );
  }
  
  if (!payload.session_id) {
    throw new AuthenticationError(
      'Token missing session identifier',
      'TOKEN_MISSING_SESSION'
    );
  }
  
  if (!Array.isArray(payload.roles)) {
    throw new AuthenticationError(
      'Token missing or invalid roles',
      'TOKEN_INVALID_ROLES'
    );
  }
  
  if (!Array.isArray(payload.permissions)) {
    throw new AuthenticationError(
      'Token missing or invalid permissions',
      'TOKEN_INVALID_PERMISSIONS'
    );
  }
  
  // Validate token is not too old (security best practice)
  const tokenAge = Date.now() / 1000 - payload.iat;
  const maxTokenAge = 24 * 60 * 60; // 24 hours
  
  if (tokenAge > maxTokenAge) {
    throw new AuthenticationError(
      'Token too old, re-authentication required',
      'TOKEN_TOO_OLD'
    );
  }
}

/**
 * Handle authentication errors with comprehensive logging
 */
function handleAuthenticationError(
  error: unknown,
  req: AuthenticatedRequest,
  res: Response,
  correlationId: string
): void {
  const authError = error instanceof AuthenticationError 
    ? error 
    : new AuthenticationError('Authentication failed', 'UNKNOWN_ERROR');
  
  // Log authentication failure
  logger.warn('🚫 Authentication failed', {
    classification: 'HIGH',
    audit_event: 'AUTHENTICATION_FAILED',
    error_code: authError.code,
    error_message: authError.message,
    correlation_id: correlationId,
    ip_address: getClientIP(req),
    user_agent: req.headers['user-agent'],
    path: req.path,
    method: req.method
  });
  
  // Audit log for security monitoring
  nuclearAuditLogger.logEvent(
    'AUTH_FAILURE' as any,
    'Authentication attempt failed',
    'FAILURE',
    {
      resource_type: 'authentication',
      resource_id: 'unknown',
      metadata: {
        error_code: authError.code,
        correlation_id: correlationId,
        ip_address: getClientIP(req),
        path: req.path,
        method: req.method,
        security_impact: 'POTENTIAL_UNAUTHORIZED_ACCESS'
      }
    }
  );
  
  // Return standardized error response
  res.status(authError.httpStatus).json({
    error: 'Authentication Required',
    message: 'Valid authentication token required',
    code: authError.code,
    correlation_id: correlationId,
    timestamp: new Date().toISOString()
  });
}

/**
 * Get client IP address with proxy support
 */
function getClientIP(req: Request): string {
  return (
    req.headers['x-forwarded-for'] as string ||
    req.headers['x-real-ip'] as string ||
    req.connection.remoteAddress ||
    req.socket.remoteAddress ||
    'unknown'
  );
}

/**
 * Generate correlation ID for request tracking
 */
function generateCorrelationId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Optional middleware for API key authentication (alternative to JWT)
 */
export function authenticateAPIKey(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const apiKey = req.headers['x-api-key'] as string;
  const correlationId = req.headers['x-correlation-id'] as string || generateCorrelationId();
  req.correlation_id = correlationId;
  
  if (!apiKey) {
    return handleAuthenticationError(
      new AuthenticationError('API key required', 'API_KEY_MISSING'),
      req,
      res,
      correlationId
    );
  }
  
  // In a real implementation, validate API key against database
  // For now, just check it's not empty and has minimum length
  if (apiKey.length < 32) {
    return handleAuthenticationError(
      new AuthenticationError('Invalid API key format', 'API_KEY_INVALID'),
      req,
      res,
      correlationId
    );
  }
  
  // Attach minimal user context for API key auth
  req.user = {
    id: 'api-key-user',
    tenant_name: 'api-tenant', // Should be derived from API key
    roles: ['api'],
    permissions: ['read', 'write'],
    session_id: correlationId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
  };
  
  logger.info('🔑 API key authentication successful', {
    classification: 'CONFIDENTIAL',
    audit_event: 'API_KEY_AUTHENTICATION_SUCCESS',
    correlation_id: correlationId,
    ip_address: getClientIP(req)
  });
  
  next();
}

/**
 * Middleware to skip authentication for health checks
 */
export function skipAuthForHealthCheck(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Skip authentication for health check endpoints
  if (req.path === '/health' || req.path === '/ping' || req.path === '/status') {
    return next();
  }
  
  // Apply authentication for all other routes
  return authenticateRequest(req as AuthenticatedRequest, res, next);
}