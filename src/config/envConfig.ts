/**
 * ?? CORE-BACKEND: Nuclear Environment Configuration
 * 
 * Centralized configuration management with security-first approach
 * All environment variables classified per ISO 27001 A.8.2.1
 * 
 * Classification: CONFIDENTIAL (contains sensitive configuration)
 * Retention: Service lifetime (operational requirement)
 * Review Date: Every 3 months (critical configuration)
 */

import dotenv from 'dotenv';

// Load environment variables with path validation
const envPath = process.env.NODE_ENV === 'test' ? '.env.test' : '.env';
dotenv.config({ path: envPath });

/**
 * Environment configuration interface with strict typing
 * All properties are classified for compliance tracking
 */
interface EnvironmentConfig {
  // ?? Database Configuration (CRITICAL classification)
  readonly pgHost: string;
  readonly pgPort: number;
  readonly pgDatabase: string;
  readonly pgUser: string;
  readonly pgPassword: string;
  
  // ?? Authentication Configuration (CRITICAL classification)
  readonly jwtSecret: string;
  
  // ?? Service Configuration (HIGH classification)
  readonly tenantId: string;
  readonly serviceName: string;
  
  // ?? Network Configuration (INTERNAL classification)
  readonly backendPort: number;
  readonly backendHost: string;
  
  // ?? Environment Configuration (INTERNAL classification)
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  
  // ?? Integration Configuration (HIGH classification)
  readonly coreEnvsPrivateUrl?: string;
  readonly healthCheckInterval: number;
  
  // ?? External Authentication Configuration (HIGH classification)
  readonly apiUrl?: string;
  readonly authUrl?: string;
  readonly authUsername?: string;
  readonly authPassword?: string;
}

/**
 * Safe string conversion with validation
 */
function requireString(key: string, defaultValue?: string): string {
  const value = process.env[key] || defaultValue;
  if (!value) {
    throw new Error(`Required environment variable ${key} is not set`);
  }
  return value;
}

/**
 * Safe number conversion with validation
 */
function requireNumber(key: string, defaultValue?: number): number {
  const value = process.env[key];
  if (!value && defaultValue === undefined) {
    throw new Error(`Required environment variable ${key} is not set`);
  }
  
  const numValue = value ? parseInt(value, 10) : defaultValue!;
  if (isNaN(numValue)) {
    throw new Error(`Environment variable ${key} must be a valid number, got: ${value}`);
  }
  
  return numValue;
}

/**
 * Safe enum conversion with validation
 */
function requireEnum<T extends string>(
  key: string, 
  allowedValues: readonly T[], 
  defaultValue?: T
): T {
  const value = process.env[key] || defaultValue;
  if (!value) {
    throw new Error(`Required environment variable ${key} is not set`);
  }
  
  if (!allowedValues.includes(value as T)) {
    throw new Error(
      `Environment variable ${key} must be one of [${allowedValues.join(', ')}], got: ${value}`
    );
  }
  
  return value as T;
}

/**
 * Nuclear environment configuration
 * Fail-fast validation with comprehensive error messages
 */
const envConfig: EnvironmentConfig = {
  // ?? Database Configuration (CRITICAL - ISO 27001 A.8.2.1)
  pgHost: requireString('PGHOST'),
  pgPort: requireNumber('PGPORT', 5432),
  pgDatabase: requireString('PGDATABASE'),
  pgUser: requireString('PGUSER'),
  pgPassword: requireString('PGPASSWORD'),
  
  // ?? Authentication Configuration (CRITICAL - ISO 27001 A.9.4.1)
  jwtSecret: requireString('JWT_SECRET'),
  
  // ?? Service Configuration (HIGH - Business Critical)
  tenantId: requireString('TENANT_ID'),
  serviceName: requireString('SERVICE_NAME', 'core-backend'),
  
  // ?? Network Configuration (INTERNAL - Operational)
  backendPort: requireNumber('BACKEND_PORT', 3000),
  backendHost: requireString('BACKEND_HOST', '0.0.0.0'),
  
  // ?? Environment Configuration (INTERNAL - Operational)
  nodeEnv: requireEnum('NODE_ENV', ['development', 'test', 'production'] as const, 'development'),
  logLevel: requireEnum('LOG_LEVEL', ['debug', 'info', 'warn', 'error'] as const, 'info'),
  
  // ?? Integration Configuration (HIGH - External Dependencies)
  coreEnvsPrivateUrl: process.env.CORE_ENVS_PRIVATE_URL,
  healthCheckInterval: requireNumber('HEALTH_CHECK_INTERVAL', 60000), // 1 minute default
  
  // ?? External Authentication Configuration (HIGH - External API)
  apiUrl: process.env.API_URL,
  authUrl: process.env.AUTH_URL,
  authUsername: process.env.AUTH_USERNAME,
  authPassword: process.env.AUTH_PASSWORD,
};

/**
 * Configuration validation for security compliance
 * Validates configuration against security requirements
 */
function validateSecurityRequirements(config: EnvironmentConfig): void {
  // JWT Secret strength validation
  if (config.jwtSecret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters for security compliance');
  }
  
  if (config.jwtSecret === 'default_secret_dangerous') {
    throw new Error('Default JWT_SECRET is not allowed in any environment');
  }
  
  // Production-specific validations
  if (config.nodeEnv === 'production') {
    // Database security in production
    if (config.pgHost === 'localhost' || config.pgHost === '127.0.0.1') {
      throw new Error('Production environment cannot use localhost database');
    }
    
    if (config.pgPassword.length < 12) {
      throw new Error('Production database password must be at least 12 characters');
    }
    
    // Network security in production
    if (config.backendPort < 1024) {
      console.warn('?? WARNING: Using privileged port in production requires root privileges');
    }
  }
  
  // Development-specific validations
  if (config.nodeEnv === 'development') {
    if (!config.pgHost.includes('localhost') && !config.pgHost.includes('127.0.0.1') && !config.pgHost.includes('dev')) {
      console.warn('?? WARNING: Development environment connecting to non-local database');
    }
  }
}

/**
 * Configuration classification for compliance tracking
 * Maps each configuration property to its ISO 27001 classification
 */
export const CONFIG_CLASSIFICATION = {
  // CRITICAL classification (A.8.2.1 - Highest security requirements)
  pgPassword: 'CRITICAL',
  jwtSecret: 'CRITICAL',
  
  // HIGH classification (Significant business impact)
  pgHost: 'HIGH',
  pgUser: 'HIGH',
  pgDatabase: 'HIGH',
  tenantId: 'HIGH',
  coreEnvsPrivateUrl: 'HIGH',
  apiUrl: 'HIGH',
  authUrl: 'HIGH',
  authUsername: 'HIGH',
  authPassword: 'HIGH',
  
  // INTERNAL classification (Internal operational data)
  pgPort: 'INTERNAL',
  serviceName: 'INTERNAL',
  backendPort: 'INTERNAL',
  backendHost: 'INTERNAL',
  nodeEnv: 'INTERNAL',
  logLevel: 'INTERNAL',
  healthCheckInterval: 'INTERNAL',
} as const;

/**
 * Get configuration value with classification context
 * Used for audit logging and compliance tracking
 */
export function getConfigWithClassification(key: keyof EnvironmentConfig): {
  value: any;
  classification: string;
  auditRequired: boolean;
} {
  const value = envConfig[key];
  const classification = CONFIG_CLASSIFICATION[key] || 'INTERNAL';
  const auditRequired = classification === 'CRITICAL' || classification === 'HIGH';
  
  // Never log CRITICAL values
  const safeValue = classification === 'CRITICAL' ? '[REDACTED]' : value;
  
  return {
    value: safeValue,
    classification,
    auditRequired
  };
}

/**
 * Validate configuration on module load
 * Ensures all requirements are met before service starts
 */
try {
  validateSecurityRequirements(envConfig);
} catch (error) {
  console.error('?? CRITICAL: Environment configuration validation failed');
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
  console.error('Service cannot start with invalid configuration');
  process.exit(1);
}

// Log successful configuration load (without sensitive data)
console.log('? Nuclear environment configuration loaded successfully', {
  nodeEnv: envConfig.nodeEnv,
  serviceName: envConfig.serviceName,
  backendPort: envConfig.backendPort,
  pgHost: envConfig.pgHost.includes('localhost') ? 'localhost' : '[REDACTED]',
  configClassifications: Object.keys(CONFIG_CLASSIFICATION).length,
  timestamp: new Date().toISOString()
});

export default envConfig;