/**
 * 🚨 CORE-BACKEND: Nuclear Authentication Controller
 * 
 * Simple but secure JWT authentication for multi-client access
 * Compatible with Oracle PL/SQL, JavaScript, Python clients
 * 
 * Classification: CONFIDENTIAL (authentication logic)
 * Retention: 7 years (security requirement)
 * Review Date: Every 3 months (critical security component)
 */

import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import envConfig from '../config/envConfig';
import logger from '../utils/logger';

/**
 * User record interface with security context
 */
interface UserRecord {
  readonly username: string;
  readonly password_hash: string;
  readonly role: string;
  readonly enabled: boolean;
  readonly created_at: string;
  readonly last_login?: string;
  readonly failed_attempts: number;
  readonly locked_until?: string;
}

/**
 * JWT payload interface
 */
interface JWTPayload {
  username: string;
  role: string;
  tenant_id: string;
  iat: number;
  exp: number;
}

/**
 * Authentication response interface
 */
interface AuthResponse {
  token: string;
  expires_in: number;
  token_type: 'Bearer';
  issued_at: string;
  user: {
    username: string;
    role: string;
    tenant_id: string;
  };
}

/**
 * Load users from core-envs-private configuration
 * This will be replaced with actual core-envs-private integration
 * For now, uses environment variables with secure defaults
 */
function loadUsersFromCoreEnvs(): Record<string, UserRecord> {
  // TODO: Replace with actual core-envs-private integration
  // For development, load from environment variables
  
  const users: Record<string, UserRecord> = {};
  
  // Core services user (primary service account)
  const coreServicesUsername = process.env.CORE_SERVICES_USERNAME || 'core-services';
  const coreServicesPassword = process.env.CORE_SERVICES_PASSWORD_HASH;
  
  if (coreServicesPassword) {
    users[coreServicesUsername] = {
      username: coreServicesUsername,
      password_hash: coreServicesPassword,
      role: 'service',
      enabled: true,
      created_at: new Date().toISOString(),
      failed_attempts: 0
    };
  }
  
  // Admin user (for administrative access)
  const adminUsername = process.env.ADMIN_USERNAME || 'admin';
  const adminPassword = process.env.ADMIN_PASSWORD_HASH;
  
  if (adminPassword) {
    users[adminUsername] = {
      username: adminUsername,
      password_hash: adminPassword,
      role: 'admin',
      enabled: true,
      created_at: new Date().toISOString(),
      failed_attempts: 0
    };
  }
  
  // Validate at least one user exists
  if (Object.keys(users).length === 0) {
    logger.error('💥 CRITICAL: No users configured for authentication', {
      classification: 'CRITICAL',
      audit_event: 'NO_USERS_CONFIGURED',
      security_impact: 'AUTHENTICATION_UNAVAILABLE'
    });
    
    throw new Error('No authentication users configured');
  }
  
  logger.info('✅ Users loaded from configuration', {
    classification: 'HIGH',
    audit_event: 'USERS_LOADED',
    user_count: Object.keys(users).length,
    usernames: Object.keys(users) // Safe to log usernames
  });
  
  return users;
}

/**
 * Get users with caching and error handling
 * Implements circuit breaker pattern for resilience
 */
let cachedUsers: Record<string, UserRecord> | null = null;
let lastUserLoad = 0;
const USER_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function getUsers(): Record<string, UserRecord> {
  const now = Date.now();
  
  // Use cached users if still valid
  if (cachedUsers && (now - lastUserLoad) < USER_CACHE_TTL) {
    return cachedUsers;
  }
  
  try {
    cachedUsers = loadUsersFromCoreEnvs();
    lastUserLoad = now;
    return cachedUsers;
  } catch (error) {
    logger.error('💥 Failed to load users', {
      classification: 'CRITICAL',
      audit_event: 'USER_LOAD_FAILED',
      error: error instanceof Error ? error.message : String(error)
    });
    
    // If we have cached users, use them as fallback
    if (cachedUsers) {
      logger.warn('⚠️ Using cached users as fallback', {
        classification: 'HIGH',
        audit_event: 'USER_CACHE_FALLBACK'
      });
      return cachedUsers;
    }
    
    throw error;
  }
}

/**
 * Validate user credentials with security controls
 */
async function validateCredentials(
  username: string, 
  password: string,
  clientIp: string,
  correlationId: string
): Promise<{ valid: boolean; user?: UserRecord; reason?: string }> {
  
  const users = getUsers();
  const user = users[username];
  
  // User not found
  if (!user) {
    logger.warn('🚫 Authentication failed - user not found', {
      classification: 'HIGH',
      audit_event: 'AUTH_USER_NOT_FOUND',
      username,
      client_ip: clientIp,
      correlation_id: correlationId
    });
    
    return { valid: false, reason: 'Invalid credentials' };
  }
  
  // User disabled
  if (!user.enabled) {
    logger.warn('🚫 Authentication failed - user disabled', {
      classification: 'HIGH',
      audit_event: 'AUTH_USER_DISABLED',
      username,
      client_ip: clientIp,
      correlation_id: correlationId
    });
    
    return { valid: false, reason: 'Account disabled' };
  }
  
  // Account locked
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    logger.warn('🚫 Authentication failed - account locked', {
      classification: 'HIGH',
      audit_event: 'AUTH_USER_LOCKED',
      username,
      locked_until: user.locked_until,
      client_ip: clientIp,
      correlation_id: correlationId
    });
    
    return { valid: false, reason: 'Account temporarily locked' };
  }
  
  // Validate password
  try {
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordValid) {
      logger.warn('🚫 Authentication failed - invalid password', {
        classification: 'HIGH',
        audit_event: 'AUTH_INVALID_PASSWORD',
        username,
        failed_attempts: user.failed_attempts + 1,
        client_ip: clientIp,
        correlation_id: correlationId
      });
      
      return { valid: false, reason: 'Invalid credentials' };
    }
    
    logger.info('✅ Authentication successful', {
      classification: 'HIGH',
      audit_event: 'AUTH_SUCCESS',
      username,
      role: user.role,
      client_ip: clientIp,
      correlation_id: correlationId
    });
    
    return { valid: true, user };
    
  } catch (error) {
    logger.error('💥 Password validation error', {
      classification: 'CRITICAL',
      audit_event: 'AUTH_VALIDATION_ERROR',
      username,
      error: error instanceof Error ? error.message : String(error),
      client_ip: clientIp,
      correlation_id: correlationId
    });
    
    return { valid: false, reason: 'Authentication error' };
  }
}

/**
 * Generate secure JWT token
 */
function generateJWT(user: UserRecord, correlationId: string): { token: string; expiresIn: number } {
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 15 * 60; // 15 minutes for security
  
  const payload: JWTPayload = {
    username: user.username,
    role: user.role,
    tenant_id: envConfig.tenantId,
    iat: now,
    exp: now + expiresIn
  };
  
  const token = jwt.sign(payload, envConfig.jwtSecret, {
    algorithm: 'HS256',
    issuer: 'core-backend',
    audience: 'core-platform'
  });
  
  logger.info('🔑 JWT token generated', {
    classification: 'HIGH',
    audit_event: 'JWT_GENERATED',
    username: user.username,
    role: user.role,
    expires_in: expiresIn,
    correlation_id: correlationId
  });
  
  return { token, expiresIn };
}

/**
 * Login endpoint
 * Authenticates user and returns JWT token
 */
export const login = async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();
  const correlationId = (req as any).correlationId || 'unknown';
  const clientIp = req.ip || 'unknown';
  
  try {
    // Input validation
    const { username, password } = req.body;
    
    if (!username || !password) {
      logger.warn('🚫 Login failed - missing credentials', {
        classification: 'HIGH',
        audit_event: 'LOGIN_MISSING_CREDENTIALS',
        has_username: !!username,
        has_password: !!password,
        client_ip: clientIp,
        correlation_id: correlationId
      });
      
      res.status(400).json({
        error: 'Username and password are required',
        correlation_id: correlationId
      });
      return;
    }
    
    // Validate input format
    if (typeof username !== 'string' || typeof password !== 'string') {
      logger.warn('🚫 Login failed - invalid input format', {
        classification: 'HIGH',
        audit_event: 'LOGIN_INVALID_FORMAT',
        username_type: typeof username,
        password_type: typeof password,
        client_ip: clientIp,
        correlation_id: correlationId
      });
      
      res.status(400).json({
        error: 'Invalid input format',
        correlation_id: correlationId
      });
      return;
    }
    
    // Validate credentials
    const validation = await validateCredentials(username, password, clientIp, correlationId);
    
    if (!validation.valid || !validation.user) {
      res.status(401).json({
        error: validation.reason || 'Authentication failed',
        correlation_id: correlationId
      });
      return;
    }
    
    // Generate JWT
    const { token, expiresIn } = generateJWT(validation.user, correlationId);
    
    // Prepare response
    const response: AuthResponse = {
      token,
      expires_in: expiresIn,
      token_type: 'Bearer',
      issued_at: new Date().toISOString(),
      user: {
        username: validation.user.username,
        role: validation.user.role,
        tenant_id: envConfig.tenantId
      }
    };
    
    const duration = Date.now() - startTime;
    
    logger.info('✅ Login successful', {
      classification: 'HIGH',
      audit_event: 'LOGIN_SUCCESS',
      username: validation.user.username,
      role: validation.user.role,
      duration_ms: duration,
      client_ip: clientIp,
      correlation_id: correlationId
    });
    
    res.status(200).json(response);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.error('💥 Login error', {
      classification: 'CRITICAL',
      audit_event: 'LOGIN_ERROR',
      error: error instanceof Error ? error.message : String(error),
      duration_ms: duration,
      client_ip: clientIp,
      correlation_id: correlationId
    });
    
    res.status(500).json({
      error: 'Internal authentication error',
      correlation_id: correlationId
    });
  }
};

/**
 * Token validation endpoint
 * Validates JWT token and returns user info
 */
export const validateToken = async (req: Request, res: Response): Promise<void> => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'Missing or invalid authorization header',
        correlation_id: correlationId
      });
      return;
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
      const payload = jwt.verify(token, envConfig.jwtSecret) as JWTPayload;
      
      logger.info('✅ Token validation successful', {
        classification: 'INTERNAL',
        audit_event: 'TOKEN_VALIDATED',
        username: payload.username,
        role: payload.role,
        correlation_id: correlationId
      });
      
      res.status(200).json({
        valid: true,
        user: {
          username: payload.username,
          role: payload.role,
          tenant_id: payload.tenant_id
        },
        expires_at: new Date(payload.exp * 1000).toISOString(),
        correlation_id: correlationId
      });
      
    } catch (jwtError) {
      logger.warn('🚫 Token validation failed', {
        classification: 'HIGH',
        audit_event: 'TOKEN_VALIDATION_FAILED',
        error: jwtError instanceof Error ? jwtError.message : String(jwtError),
        correlation_id: correlationId
      });
      
      res.status(401).json({
        error: 'Invalid or expired token',
        correlation_id: correlationId
      });
    }
    
  } catch (error) {
    logger.error('💥 Token validation error', {
      classification: 'CRITICAL',
      audit_event: 'TOKEN_VALIDATION_ERROR',
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId
    });
    
    res.status(500).json({
      error: 'Token validation error',
      correlation_id: correlationId
    });
  }
};

/**
 * Token refresh endpoint (optional)
 * Refreshes JWT token if still valid
 */
export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'Missing or invalid authorization header',
        correlation_id: correlationId
      });
      return;
    }
    
    const token = authHeader.split(' ')[1];
    
    try {
      // Verify current token (even if expired, we check the payload)
      const payload = jwt.verify(token, envConfig.jwtSecret, { ignoreExpiration: true }) as JWTPayload;
      
      // Check if token is not too old (max 1 hour for refresh)
      const now = Math.floor(Date.now() / 1000);
      const tokenAge = now - payload.iat;
      const maxRefreshAge = 60 * 60; // 1 hour
      
      if (tokenAge > maxRefreshAge) {
        res.status(401).json({
          error: 'Token too old for refresh',
          correlation_id: correlationId
        });
        return;
      }
      
      // Get user to ensure still valid
      const users = getUsers();
      const user = users[payload.username];
      
      if (!user || !user.enabled) {
        res.status(401).json({
          error: 'User no longer valid',
          correlation_id: correlationId
        });
        return;
      }
      
      // Generate new token
      const { token: newToken, expiresIn } = generateJWT(user, correlationId);
      
      logger.info('🔄 Token refreshed', {
        classification: 'HIGH',
        audit_event: 'TOKEN_REFRESHED',
        username: payload.username,
        correlation_id: correlationId
      });
      
      res.status(200).json({
        token: newToken,
        expires_in: expiresIn,
        token_type: 'Bearer',
        issued_at: new Date().toISOString(),
        correlation_id: correlationId
      });
      
    } catch (jwtError) {
      res.status(401).json({
        error: 'Invalid token for refresh',
        correlation_id: correlationId
      });
    }
    
  } catch (error) {
    logger.error('💥 Token refresh error', {
      classification: 'CRITICAL',
      audit_event: 'TOKEN_REFRESH_ERROR',
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId
    });
    
    res.status(500).json({
      error: 'Token refresh error',
      correlation_id: correlationId
    });
  }
};