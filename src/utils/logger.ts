/**
 * 🚨 CORE-BACKEND: Nuclear Structured Logger
 * 
 * Compliance-ready structured logging with comprehensive security
 * Supports ISO 27001, GDPR, and Zero Trust audit requirements
 * 
 * Classification: CONFIDENTIAL (logging infrastructure)
 * Retention: 7 years (audit requirement)
 * Review Date: Every 3 months (critical security component)
 */

import { createLogger, format, transports, Logger } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';
import fs from 'fs';

/**
 * Log entry interface for structured logging
 * Ensures compliance with audit and security requirements
 */
interface LogEntry {
  // Core log data
  message: string;
  level?: 'debug' | 'info' | 'warn' | 'error';
  
  // Compliance fields (ISO 27001 A.12.4.1)
  classification?: 'PUBLIC' | 'INTERNAL' | 'HIGH' | 'CONFIDENTIAL' | 'CRITICAL';
  audit_event?: string;
  
  // Correlation and tracing
  correlation_id?: string;
  trace_id?: string;
  
  // Security context
  user_id?: string;
  client_ip?: string;
  user_agent?: string;
  
  // Business context
  tenant_name?: string;
  service?: string;
  action?: string;
  
  // Technical context
  duration_ms?: number;
  error_code?: string;
  stack?: string;
  
  // Additional structured data
  [key: string]: any;
}

/**
 * Classification-based log levels
 * Maps ISO 27001 classifications to appropriate log levels
 */
const CLASSIFICATION_LEVELS: Record<string, string> = {
  'PUBLIC': 'info',
  'INTERNAL': 'info', 
  'HIGH': 'warn',
  'CONFIDENTIAL': 'warn',
  'CRITICAL': 'error'
};

/**
 * Sensitive field patterns for data sanitization
 * Prevents logging of sensitive information
 */
const SENSITIVE_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /key/i,
  /auth/i,
  /credential/i,
  /private/i
];

/**
 * Sanitize log data to prevent sensitive information leakage
 * Implements data protection for compliance
 */
function sanitizeLogData(data: any): any {
  if (typeof data !== 'object' || data === null) {
    return data;
  }
  
  if (Array.isArray(data)) {
    return data.map(sanitizeLogData);
  }
  
  const sanitized: any = {};
  
  for (const [key, value] of Object.entries(data)) {
    // Check if key contains sensitive patterns
    const isSensitive = SENSITIVE_PATTERNS.some(pattern => pattern.test(key));
    
    if (isSensitive) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeLogData(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

/**
 * Custom log formatter for structured output
 * Provides both human-readable and machine-parseable formats
 */
const structuredFormat = format.printf((info) => {
  const {
    timestamp,
    level,
    message,
    classification = 'INTERNAL',
    audit_event,
    correlation_id,
    ...meta
  } = info;
  
  // Sanitize metadata
  const sanitizedMeta = sanitizeLogData(meta);
  
  // Build structured log entry
  const logEntry: any = {
    timestamp,
    level: level.toUpperCase(),
    classification,
    message
  };
  
  if (audit_event) {
    logEntry.audit_event = audit_event;
  }
  
  if (correlation_id) {
    logEntry.correlation_id = correlation_id;
  }
  
  if (Object.keys(sanitizedMeta).length > 0) {
    logEntry.metadata = sanitizedMeta;
  }
  
  return JSON.stringify(logEntry);
});

/**
 * Human-readable format for console output
 * Provides colored, readable logs for development
 */
const consoleFormat = format.printf((info) => {
  const {
    timestamp,
    level,
    message,
    classification = 'INTERNAL',
    correlation_id,
    audit_event,
    ...meta
  } = info;
  
  let output = `${timestamp} [${level.toUpperCase()}]`;
  
  if (classification !== 'INTERNAL') {
    output += ` [${classification}]`;
  }
  
  if (correlation_id && typeof correlation_id === 'string') {
    output += ` [${correlation_id.substring(0, 8)}]`;
  }
  
  output += `: ${message}`;
  
  if (audit_event) {
    output += ` (${audit_event})`;
  }
  
  // Add metadata if present (simplified for console)
  const sanitizedMeta = sanitizeLogData(meta);
  if (Object.keys(sanitizedMeta).length > 0) {
    output += ` ${JSON.stringify(sanitizedMeta)}`;
  }
  
  return output;
});

/**
 * Create logs directory if it doesn't exist
 */
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Determine log level from environment with security defaults
 */
const getLogLevel = (): string => {
  const envLevel = process.env.LOG_LEVEL?.toLowerCase();
  const validLevels = ['debug', 'info', 'warn', 'error'];
  
  if (envLevel && validLevels.includes(envLevel)) {
    return envLevel;
  }
  
  // Security-first defaults
  return process.env.NODE_ENV === 'production' ? 'info' : 'debug';
};

/**
 * Nuclear Winston logger configuration
 * Implements comprehensive logging with security and compliance
 */
const nuclearLogger = createLogger({
  level: getLogLevel(),
  
  // Default format for structured logging
  format: format.combine(
    format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss.SSS'
    }),
    format.errors({ stack: true }),
    structuredFormat
  ),
  
  // Transport configuration
  transports: [
    // Console output (development-friendly)
    new transports.Console({
      level: getLogLevel(),
      format: format.combine(
        format.colorize({
          colors: {
            debug: 'blue',
            info: 'green', 
            warn: 'yellow',
            error: 'red'
          }
        }),
        format.timestamp({
          format: 'HH:mm:ss.SSS'
        }),
        consoleFormat
      )
    }),
    
    // Application logs with daily rotation
    new DailyRotateFile({
      filename: path.join(logsDir, 'core-backend-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '100m',      // Max 100MB per file
      maxFiles: '30d',      // Keep 30 days
      level: 'info',
      format: structuredFormat
    }),
    
    // Error logs (separate file for critical issues)
    new DailyRotateFile({
      filename: path.join(logsDir, 'core-backend-error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '50m',       // Max 50MB per file
      maxFiles: '90d',      // Keep 90 days for errors
      level: 'error',
      format: structuredFormat
    }),
    
    // Audit logs (compliance-specific)
    new DailyRotateFile({
      filename: path.join(logsDir, 'core-backend-audit-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '200m',      // Larger for audit trails
      maxFiles: '2555d',    // 7 years retention (ISO 27001)
      level: 'info',
      format: format.combine(
        format.timestamp({
          format: 'YYYY-MM-DD HH:mm:ss.SSS'
        }),
        format.errors({ stack: true }),
        // Custom filter format for audit events only
        format((info) => {
          return info.audit_event ? info : false;
        })(),
        structuredFormat
      )
    })
  ],
  
  // Exception handling
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'core-backend-exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '50m',
      maxFiles: '90d'
    })
  ],
  
  // Rejection handling (unhandled promise rejections)
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'core-backend-rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '50m',
      maxFiles: '90d'
    })
  ],
  
  // Don't exit on handled exceptions
  exitOnError: false
});

/**
 * Enhanced logger interface with compliance support
 * Provides methods for structured, compliant logging
 */
class NuclearLogger {
  private logger: Logger;
  
  constructor(logger: Logger) {
    this.logger = logger;
  }
  
  /**
   * Debug logging (development and troubleshooting)
   */
  debug(message: string, meta?: Partial<LogEntry>): void {
    this.log('debug', message, meta);
  }
  
  /**
   * Info logging (general operational information)
   */
  info(message: string, meta?: Partial<LogEntry>): void {
    this.log('info', message, meta);
  }
  
  /**
   * Warning logging (potential issues)
   */
  warn(message: string, meta?: Partial<LogEntry>): void {
    this.log('warn', message, meta);
  }
  
  /**
   * Error logging (errors and failures)
   */
  error(message: string, meta?: Partial<LogEntry>): void {
    this.log('error', message, meta);
  }
  
  /**
   * Audit logging (compliance and security events)
   */
  audit(auditEvent: string, message: string, meta?: Partial<LogEntry>): void {
    this.log('info', message, {
      ...meta,
      audit_event: auditEvent,
      classification: meta?.classification || 'HIGH'
    });
  }
  
  /**
   * Security logging (security-relevant events)
   */
  security(message: string, meta?: Partial<LogEntry>): void {
    this.log('warn', message, {
      ...meta,
      classification: 'CRITICAL',
      audit_event: meta?.audit_event || 'SECURITY_EVENT'
    });
  }
  
  /**
   * Compliance logging (regulatory compliance events)
   */
  compliance(message: string, meta?: Partial<LogEntry>): void {
    this.log('info', message, {
      ...meta,
      classification: 'CONFIDENTIAL',
      audit_event: meta?.audit_event || 'COMPLIANCE_EVENT'
    });
  }
  
  /**
   * Core logging method with classification-based level adjustment
   */
  private log(level: string, message: string, meta?: Partial<LogEntry>): void {
    const classification = meta?.classification || 'INTERNAL';
    
    // Adjust log level based on classification
    const adjustedLevel = CLASSIFICATION_LEVELS[classification] || level;
    
    // Add timestamp if not present
    const enhancedMeta = {
      ...meta,
      classification,
      timestamp: new Date().toISOString()
    };
    
    this.logger.log(adjustedLevel, message, enhancedMeta);
  }
  
  /**
   * Create child logger with default metadata
   */
  child(defaultMeta: Partial<LogEntry>): NuclearLogger {
    const childLogger = this.logger.child(defaultMeta);
    return new NuclearLogger(childLogger);
  }
}

// Create and export nuclear logger instance
const logger = new NuclearLogger(nuclearLogger);

// Log successful initialization
logger.info('🚀 Nuclear logger initialized', {
  classification: 'INTERNAL',
  audit_event: 'LOGGER_INITIALIZED',
  log_level: getLogLevel(),
  environment: process.env.NODE_ENV || 'development',
  logs_directory: logsDir
});

export default logger;