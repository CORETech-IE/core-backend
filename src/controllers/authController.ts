/**
 * 🚨 CORE-BACKEND: Authentication Controller (SIMPLIFIED)
 * 
 * JWT authentication for multi-client access
 */

import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import envConfig from '../config/envConfig';
import logger from '../utils/logger';

/**
 * User record interface
 */
interface UserRecord {
  readonly username: string;
  readonly password_hash: string;
  readonly role: string;
  readonly enabled: boolean;
  readonly created_at: string;
  readonly failed_attempts: number;
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
 * Get users - TEMPORAL hardcoded
 * TODO: Migrar a SOPS cuando esté estable
 */
function getUsers(): Record<string, UserRecord> {
  return {
    "admin": {
      username: "admin",
      password_hash: "$2b$12$n9mBEWXteAgZCOayuN7C3OcWbajiLhwUT1kLosnDakiNlKiWdV7c.",
      role: "admin",
      enabled: true,
      created_at: new Date().toISOString(),
      failed_attempts: 0
    },
    "core-services": {
      username: "core-services", 
      password_hash: "$2b$12$iSjq0bMgi/3lgMZVh85ie.2OKXMFAM1kuZHu31mP8yMaPjF.lJkWi",
      role: "service",
      enabled: true,
      created_at: new Date().toISOString(),
      failed_attempts: 0
    }
  };
}

/**
 * Validate user credentials
 */
async function validateCredentials(
  username: string, 
  password: string
): Promise<{ valid: boolean; user?: UserRecord; reason?: string }> {
  
  const users = getUsers();
  const user = users[username];
  
  if (!user) {
    logger.warn('Authentication failed - user not found', { username });
    return { valid: false, reason: 'Invalid credentials' };
  }
  
  if (!user.enabled) {
    logger.warn('Authentication failed - user disabled', { username });
    return { valid: false, reason: 'Account disabled' };
  }

  // 🔍 DEBUG TEMPORAL - BORRAR DESPUÉS
  console.log('🔐 Debug auth:', {
    username,
    password_received: password,
    stored_hash: user.password_hash,
    hash_starts_with: user.password_hash.substring(0, 7)
  });
  
  try {
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordValid) {
      logger.warn('Authentication failed - invalid password', { username });
      return { valid: false, reason: 'Invalid credentials' };
    }
    
    logger.info('Authentication successful', { username, role: user.role });
    return { valid: true, user };
    
  } catch (error) {
    logger.error('Password validation error', {
      username,
      error: error instanceof Error ? error.message : String(error)
    });
    return { valid: false, reason: 'Authentication error' };
  }
}

/**
 * Generate JWT token
 */
function generateJWT(user: UserRecord): { token: string; expiresIn: number } {
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 15 * 60; // 15 minutes
  
  const payload = {
    sub: user.username,  // ← AÑADE ESTO
    username: user.username,
    tenant_name: envConfig.tenantId,  // ← Cambiar de tenant_id a tenant_name
    roles: [user.role],  // ← Array en vez de string
    permissions: user.role === 'admin' ? ['read', 'write', 'delete'] : ['read', 'write'],
    session_id: `session-${Date.now()}`,
    iat: now,
    exp: now + expiresIn
  };
  
  const token = jwt.sign(payload, envConfig.jwtSecret, {
    algorithm: 'HS256'
  });
  
  return { token, expiresIn };
}

/**
 * Login endpoint
 */
export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      res.status(400).json({
        error: 'Username and password are required'
      });
      return;
    }
    
    const validation = await validateCredentials(username, password);
    
    if (!validation.valid || !validation.user) {
      res.status(401).json({
        error: validation.reason || 'Authentication failed'
      });
      return;
    }
    
    const { token, expiresIn } = generateJWT(validation.user);
    
    res.status(200).json({
      token,
      expires_in: expiresIn,
      token_type: 'Bearer',
      issued_at: new Date().toISOString(),
      user: {
        username: validation.user.username,
        role: validation.user.role,
        tenant_id: envConfig.tenantId
      }
    });
    
  } catch (error) {
    logger.error('Login error', {
      error: error instanceof Error ? error.message : String(error)
    });
    
    res.status(500).json({
      error: 'Internal authentication error'
    });
  }
};

/**
 * Validate token endpoint
 */
export const validateToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'Missing or invalid authorization header'
      });
      return;
    }
    
    const token = authHeader.split(' ')[1];
    const payload = jwt.verify(token, envConfig.jwtSecret) as JWTPayload;
    
    res.status(200).json({
      valid: true,
      user: {
        username: payload.username,
        role: payload.role,
        tenant_id: payload.tenant_id
      },
      expires_at: new Date(payload.exp * 1000).toISOString()
    });
    
  } catch (error) {
    res.status(401).json({
      error: 'Invalid or expired token'
    });
  }
};

/**
 * Refresh token endpoint
 */
export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'Missing or invalid authorization header'
      });
      return;
    }
    
    const token = authHeader.split(' ')[1];
    const payload = jwt.verify(token, envConfig.jwtSecret, { 
      ignoreExpiration: true 
    }) as JWTPayload;
    
    // Check if token is not too old
    const now = Math.floor(Date.now() / 1000);
    const tokenAge = now - payload.iat;
    
    if (tokenAge > 3600) { // 1 hour max
      res.status(401).json({
        error: 'Token too old for refresh'
      });
      return;
    }
    
    // Verify user still exists and is valid
    const users = getUsers();
    const user = users[payload.username];
    
    if (!user || !user.enabled) {
      res.status(401).json({
        error: 'User no longer valid'
      });
      return;
    }
    
    const { token: newToken, expiresIn } = generateJWT(user);
    
    res.status(200).json({
      token: newToken,
      expires_in: expiresIn,
      token_type: 'Bearer',
      issued_at: new Date().toISOString()
    });
    
  } catch (error) {
    res.status(401).json({
      error: 'Invalid token for refresh'
    });
  }
};