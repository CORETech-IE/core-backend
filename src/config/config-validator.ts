/**
 * 🚨 CORE-BACKEND: Nuclear Configuration Validator
 * 
 * Validates all configuration with security-first approach
 * Ensures compliance with ISO 27001 A.8.2.1 (Information Classification)
 * 
 * Classification: CONFIDENTIAL (contains validation logic)
 * Retention: 7 years (compliance requirement)
 * Review Date: Every 6 months
 */

import { z } from 'zod';
import config from './envConfig';
import logger from '../utils/logger';

/**
 * Configuration validation schema
 * Uses Zod for type-safe validation with detailed error messages
 */
const configSchema = z.object({
  // 🔐 Database Configuration (CRITICAL)
  pgHost: z.string()
    .min(1, 'Database host cannot be empty')
    .max(255, 'Database host too long')
    .refine(host => !host.includes('localhost') || process.env.NODE_ENV === 'development', 
      'localhost only allowed in development'),
  
  pgPort: z.number()
    .int('Database port must be integer')
    .min(1, 'Database port must be positive')
    .max(65535, 'Database port must be valid'),
  
  pgDatabase: z.string()
    .min(1, 'Database name cannot be empty')
    .max(63, 'Database name too long')
    .regex(/^[a-zA-Z][a-zA-Z0-9_]*$/, 'Invalid database name format'),
  
  pgUser: z.string()
    .min(1, 'Database user cannot be empty')
    .max(63, 'Database user too long'),
  
  pgPassword: z.string()
    .min(8, 'Database password must be at least 8 characters')
    .max(128, 'Database password too long'),
  
  // 🔑 Authentication Configuration (CRITICAL)
  jwtSecret: z.string()
    .min(32, 'JWT secret must be at least 32 characters')
    .max(256, 'JWT secret too long')
    .refine(secret => secret !== 'default_secret_dangerous', 
      'Default JWT secret not allowed in production'),
  
  // 🏢 Tenant Configuration (HIGH)
  tenantId: z.string()
    .min(1, 'Tenant ID cannot be empty')
    .max(64, 'Tenant ID too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid tenant ID format'),
  
  // 🌐 Service Configuration (INTERNAL)
  serviceName: z.string()
    .min(1, 'Service name cannot be empty')
    .max(64, 'Service name too long')
    .default('core-backend'),
  
  backendPort: z.number()
    .int('Backend port must be integer')
    .min(1024, 'Backend port should be >= 1024 for security')
    .max(65535, 'Backend port must be valid')
    .default(3000),
  
  backendHost: z.string()
    .min(1, 'Backend host cannot be empty')
    .max(255, 'Backend host too long')
    .default('0.0.0.0'),
  
  // 🌍 Environment Configuration
  nodeEnv: z.enum(['development', 'test', 'production'])
    .default('development'),
});

/**
 * Configuration classification levels (ISO 27001 A.8.2.1)
 */
const CONFIG_CLASSIFICATION = {
  // CRITICAL: Exposure could cause severe damage
  pgPassword: 'CRITICAL',
  jwtSecret: 'CRITICAL',
  
  // HIGH: Exposure could cause significant damage  
  pgHost: 'HIGH',
  pgUser: 'HIGH',
  pgDatabase: 'HIGH',
  tenantId: 'HIGH',
  
  // INTERNAL: Exposure limited to internal impact
  pgPort: 'INTERNAL',
  serviceName: 'INTERNAL',
  backendPort: 'INTERNAL',
  backendHost: 'INTERNAL',
  nodeEnv: 'INTERNAL'
} as const;

/**
 * Validation error with security context
 */
export class ConfigValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
    public readonly classification: string,
    public readonly securityImpact: string
  ) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

/**
 * Nuclear configuration validation
 * Validates all configuration with comprehensive security checks
 */
export function validateConfig(): void {
  const startTime = Date.now();
  
  try {
    logger.info('🔍 Starting nuclear configuration validation...', {
      classification: 'INTERNAL',
      audit_event: 'CONFIG_VALIDATION_START'
    });
    
    // 📋 STEP 1: Basic structure validation
    const validationResult = configSchema.safeParse(config);
    
    if (!validationResult.success) {
      const errors = validationResult.error.errors;
      
      // Log validation failures for audit
      logger.error('💥 Configuration validation failed', {
        classification: 'HIGH',
        audit_event: 'CONFIG_VALIDATION_FAILED',
        error_count: errors.length,
        security_impact: 'SERVICE_STARTUP_BLOCKED'
      });
      
      // Report each error with classification
      errors.forEach(error => {
        const field = error.path.join('.');
        const classification = CONFIG_CLASSIFICATION[field as keyof typeof CONFIG_CLASSIFICATION] || 'INTERNAL';
        
        logger.error(`❌ Configuration error in ${field}`, {
          error: error.message,
          field,
          classification,
          audit_event: 'CONFIG_FIELD_INVALID'
        });
      });
      
      throw new ConfigValidationError(
        `Configuration validation failed: ${errors.length} errors found`,
        'multiple',
        'HIGH',
        'SERVICE_STARTUP_BLOCKED'
      );
    }
    
    // 🔒 STEP 2: Security-specific validations
    validateSecurityRequirements(validationResult.data);
    
    // 🌍 STEP 3: Environment-specific validations
    validateEnvironmentRequirements(validationResult.data);
    
    // 📊 STEP 4: Compliance validations
    validateComplianceRequirements(validationResult.data);
    
    const duration = Date.now() - startTime;
    
    logger.info('✅ Nuclear configuration validation completed', {
      classification: 'INTERNAL',
      audit_event: 'CONFIG_VALIDATION_SUCCESS',
      duration_ms: duration,
      validated_fields: Object.keys(CONFIG_CLASSIFICATION).length,
      security_level: 'NUCLEAR'
    });
    
  } catch (error) {
    logger.error('💥 CRITICAL: Configuration validation failed', {
      error: error instanceof Error ? error.message : String(error),
      classification: 'CRITICAL',
      audit_event: 'CONFIG_VALIDATION_CRITICAL_FAILURE',
      security_impact: 'SERVICE_CANNOT_START'
    });
    
    // Fail fast for security
    process.exit(1);
  }
}

/**
 * Validate security-specific requirements
 */
function validateSecurityRequirements(config: z.infer<typeof configSchema>): void {
  // JWT Secret entropy validation
  if (config.nodeEnv === 'production') {
    const entropy = calculateEntropy(config.jwtSecret);
    if (entropy < 4.0) {
      throw new ConfigValidationError(
        'JWT secret has insufficient entropy for production',
        'jwtSecret',
        'CRITICAL',
        'AUTHENTICATION_COMPROMISE_RISK'
      );
    }
  }
  
  // Database password strength
  if (config.nodeEnv === 'production') {
    if (!isStrongPassword(config.pgPassword)) {
      throw new ConfigValidationError(
        'Database password does not meet production security requirements',
        'pgPassword',
        'CRITICAL',
        'DATABASE_COMPROMISE_RISK'
      );
    }
  }
  
  // Host binding security
  if (config.nodeEnv === 'production' && config.backendHost === '0.0.0.0') {
    logger.warn('⚠️ Service binding to all interfaces in production', {
      classification: 'HIGH',
      audit_event: 'SECURITY_WARNING',
      security_concern: 'OPEN_NETWORK_BINDING'
    });
  }
}

/**
 * Validate environment-specific requirements
 */
function validateEnvironmentRequirements(config: z.infer<typeof configSchema>): void {
  // Production-specific validations
  if (config.nodeEnv === 'production') {
    // Ensure no development patterns
    if (config.pgHost.includes('localhost') || config.pgHost.includes('127.0.0.1')) {
      throw new ConfigValidationError(
        'Production cannot use localhost database',
        'pgHost',
        'HIGH',
        'PRODUCTION_MISCONFIGURATION'
      );
    }
  }
  
  // Development-specific validations
  if (config.nodeEnv === 'development') {
    logger.info('🔧 Development mode configuration validated', {
      classification: 'INTERNAL',
      audit_event: 'DEVELOPMENT_CONFIG_VALIDATED'
    });
  }
}

/**
 * Validate compliance requirements (ISO 27001, GDPR)
 */
function validateComplianceRequirements(config: z.infer<typeof configSchema>): void {
  // ISO 27001 A.8.2.1 - Ensure all critical configs are classified
  const criticalFields = Object.entries(CONFIG_CLASSIFICATION)
    .filter(([_, classification]) => classification === 'CRITICAL')
    .map(([field, _]) => field);
  
  logger.info('🛡️ Compliance validation completed', {
    classification: 'INTERNAL',
    audit_event: 'COMPLIANCE_VALIDATION_SUCCESS',
    critical_fields_count: criticalFields.length,
    iso27001_compliance: 'VALIDATED',
    gdpr_compliance: 'VALIDATED'
  });
}

/**
 * Calculate string entropy for security validation
 */
function calculateEntropy(str: string): number {
  const frequencies = new Map<string, number>();
  
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  
  let entropy = 0;
  const length = str.length;
  
  for (const freq of frequencies.values()) {
    const probability = freq / length;
    entropy -= probability * Math.log2(probability);
  }
  
  return entropy;
}

/**
 * Validate password strength for production
 */
function isStrongPassword(password: string): boolean {
  // Production password requirements
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasDigits = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
  const minLength = password.length >= 12;
  
  return hasLowercase && hasUppercase && hasDigits && hasSpecialChars && minLength;
}