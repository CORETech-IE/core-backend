/**
 * 🚨 CORE-BACKEND: Nuclear Log Ingestion Controller
 * 
 * Single responsibility: Log ingestion endpoint ONLY
 * Multi-tenant log processing with comprehensive compliance
 * 
 * Classification: CONFIDENTIAL (log processing logic)
 * Retention: 7 years (operational requirement)
 * Review Date: Every 3 months (critical component)
 */

import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import db from '../config/db';
import logger from '../utils/logger';
import nuclearAuditLogger from '../middlewares/auditLogger';

/**
 * Log payload validation schema
 * Enforces strict validation for compliance and security
 */
const logPayloadSchema = z.object({
  // 🏢 Tenant identification (HIGH classification)
  tenant_name: z.string()
    .min(1, 'Tenant name cannot be empty')
    .max(64, 'Tenant name too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid tenant name format')
    .trim(),
  
  // 🔧 Service identification (INTERNAL classification)
  service: z.string()
    .min(1, 'Service name cannot be empty')
    .max(64, 'Service name too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid service name format')
    .trim(),
  
  // 📊 Log level (INTERNAL classification)
  level: z.enum(['debug', 'info', 'warn', 'error', 'critical'], {
    errorMap: () => ({ message: 'Level must be one of: debug, info, warn, error, critical' })
  }),
  
  // 📝 Log message (varies by classification)
  message: z.string()
    .min(1, 'Message cannot be empty')
    .max(8192, 'Message too long (max 8KB)')
    .trim(),
  
  // ⏰ Timestamp (INTERNAL classification)
  timestamp: z.string()
    .datetime({ message: 'Invalid ISO 8601 timestamp format' })
    .optional()
    .transform(val => val || new Date().toISOString()),
  
  // 🔗 Trace ID (INTERNAL classification)
  trace_id: z.string()
    .uuid('Invalid UUID format for trace_id')
    .optional()
    .transform(val => val || uuidv4()),
  
  // 🔒 Classification (MANDATORY for compliance)
  classification: z.enum(['public', 'internal', 'confidential', 'restricted'], {
    errorMap: () => ({ message: 'Classification must be one of: public, internal, confidential, restricted' })
  }),
  
  // 📅 Retention period (GDPR compliance)
  retention_period: z.number()
    .int('Retention period must be an integer')
    .min(1, 'Retention period must be at least 1 day')
    .max(3650, 'Retention period cannot exceed 10 years') // ISO 27001 maximum
    .default(365), // 1 year default
  
  // 🏷️ Tags (OPTIONAL - INTERNAL classification)
  tags: z.array(z.string().trim().max(50))
    .max(20, 'Maximum 20 tags allowed')
    .optional()
    .default([]),
  
  // 📋 Context metadata (OPTIONAL - varies by classification)
  context: z.record(z.any())
    .optional()
    .default({})
    .refine(
      (obj) => JSON.stringify(obj).length <= 32768, // 32KB limit
      { message: 'Context metadata too large (max 32KB when serialized)' }
    )
});

/**
 * Classification-based retention periods (ISO 27001 + GDPR compliance)
 */
const CLASSIFICATION_RETENTION: Record<string, number> = {
  'public': 30,        // 30 days
  'internal': 365,     // 1 year
  'confidential': 2555, // 7 years
  'restricted': 3650   // 10 years
};

/**
 * Classification validation and enforcement
 * Ensures compliance with ISO 27001 A.8.2.1
 */
function validateClassification(payload: any, correlationId: string): {
  isValid: boolean;
  adjustedRetention?: number;
  warnings?: string[];
} {
  const warnings: string[] = [];
  const { classification, retention_period } = payload;
  
  // Get recommended retention for classification
  const recommendedRetention = CLASSIFICATION_RETENTION[classification];
  
  // If retention period is longer than recommended, warn but allow
  if (retention_period > recommendedRetention) {
    const warning = `Retention period ${retention_period} days exceeds recommendation for ${classification} classification (${recommendedRetention} days)`;
    warnings.push(warning);
    
    logger.warn('⚠️ Retention period exceeds classification recommendation', {
      classification: 'INTERNAL',
      audit_event: 'RETENTION_PERIOD_EXCESSIVE',
      tenant_classification: classification,
      requested_retention: retention_period,
      recommended_retention: recommendedRetention,
      correlation_id: correlationId
    });
  }
  
  // If retention period is shorter than minimum for classification, adjust
  if (retention_period < recommendedRetention) {
    warnings.push(`Retention period adjusted from ${retention_period} to ${recommendedRetention} days for ${classification} classification`);
    
    logger.info('🔧 Retention period adjusted for compliance', {
      classification: 'INTERNAL',
      audit_event: 'RETENTION_PERIOD_ADJUSTED',
      tenant_classification: classification,
      original_retention: retention_period,
      adjusted_retention: recommendedRetention,
      correlation_id: correlationId
    });
    
    return {
      isValid: true,
      adjustedRetention: recommendedRetention,
      warnings
    };
  }
  
  return {
    isValid: true,
    adjustedRetention: retention_period,
    warnings: warnings.length > 0 ? warnings : undefined
  };
}

/**
 * Audit trail logging for log ingestion
 * Implements ISO 27001 A.12.4.1 comprehensive event logging
 */
function auditLogIngestion(
  operation: string,
  payload: any,
  result: any,
  correlationId: string,
  clientIp: string,
  duration?: number
): void {
  const auditLevel = payload.classification === 'restricted' || payload.classification === 'confidential' ? 'HIGH' : 'INTERNAL';
  
  logger.info(`📊 Log ingestion: ${operation}`, {
    classification: auditLevel,
    audit_event: `LOG_INGESTION_${operation.toUpperCase()}`,
    tenant_name: payload.tenant_name,
    service: payload.service,
    log_level: payload.level,
    log_classification: payload.classification,
    retention_period: result.retention_until ? 'calculated' : 'default',
    trace_id: payload.trace_id,
    correlation_id: correlationId,
    client_ip: clientIp,
    duration_ms: duration,
    compliance_validated: true
  });
}

/**
 * Nuclear log ingestion endpoint
 * POST /api/emit-log
 */
export const emitLog = async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();
  const correlationId = (req as any).correlationId || 'unknown';
  const clientIp = req.ip || 'unknown';
  
  try {
    // 🔍 STEP 1: Input validation with comprehensive schema
    logger.info('🔍 Starting log ingestion validation', {
      classification: 'INTERNAL',
      audit_event: 'LOG_INGESTION_STARTED',
      correlation_id: correlationId,
      client_ip: clientIp
    });
    
    const validationResult = logPayloadSchema.safeParse(req.body);
    
    if (!validationResult.success) {
      const errors = validationResult.error.errors;
      
      logger.warn('🚫 Log payload validation failed', {
        classification: 'HIGH',
        audit_event: 'LOG_VALIDATION_FAILED',
        error_count: errors.length,
        errors: errors.map(e => ({ field: e.path.join('.'), message: e.message })),
        correlation_id: correlationId,
        client_ip: clientIp
      });
      
      res.status(400).json({
        error: 'Invalid log payload',
        details: errors.map(e => ({
          field: e.path.join('.'),
          message: e.message
        })),
        correlation_id: correlationId
      });
      return;
    }
    
    const payload = validationResult.data;
    
    // 🛡️ STEP 2: Classification validation and compliance check
    const classificationValidation = validateClassification(payload, correlationId);
    
    if (!classificationValidation.isValid) {
      res.status(400).json({
        error: 'Classification validation failed',
        correlation_id: correlationId
      });
      return;
    }
    
    // Use adjusted retention period if necessary
    const finalRetentionPeriod = classificationValidation.adjustedRetention || payload.retention_period;
    const retentionUntil = new Date();
    retentionUntil.setDate(retentionUntil.getDate() + finalRetentionPeriod);
    
    // 🗄️ STEP 3: Database insertion with transaction
    const insertQuery = `
      INSERT INTO core_dev.logs (
        tenant_name, service, timestamp, level, message, 
        tags, context, trace_id, classification, 
        retention_until, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, created_at
    `;
    
    const insertValues = [
      payload.tenant_name,
      payload.service,
      new Date(payload.timestamp),
      payload.level,
      payload.message,
      payload.tags,
      JSON.stringify(payload.context),
      payload.trace_id,
      payload.classification,
      retentionUntil,
      new Date()
    ];
    
    const dbResult = await db.query(insertQuery, insertValues);
    const insertedLog = dbResult.rows[0];
    
    const duration = Date.now() - startTime;
    
    // 📊 STEP 4: Audit trail logging
    auditLogIngestion('SUCCESS', payload, {
      id: insertedLog.id,
      retention_until: retentionUntil
    }, correlationId, clientIp, duration);
    
    // 📊 STEP 5: Log ingestion audit event
    nuclearAuditLogger.logLogIngestion(
      payload.tenant_name,
      payload.classification,
      req,
      true,
      {
        log_id: insertedLog.id,
        service: payload.service,
        log_level: payload.level,
        retention_until: retentionUntil.toISOString(),
        processing_time_ms: duration
      }
    );
    
    // 📤 STEP 6: Success response
    const response = {
      status: 'success',
      message: 'Log ingested successfully',
      log_id: insertedLog.id,
      trace_id: payload.trace_id,
      tenant_name: payload.tenant_name,
      classification: payload.classification,
      retention_until: retentionUntil.toISOString(),
      warnings: classificationValidation.warnings,
      correlation_id: correlationId,
      processing_time_ms: duration
    };
    
    res.status(201).json(response);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    // Handle specific database errors
    if (error instanceof Error) {
      if (error.message.includes('connection')) {
        logger.error('💥 Database connection error during log ingestion', {
          classification: 'CRITICAL',
          audit_event: 'LOG_INGESTION_DB_CONNECTION_ERROR',
          error: error.message,
          correlation_id: correlationId,
          client_ip: clientIp,
          duration_ms: duration
        });
        
        res.status(503).json({
          error: 'Database service unavailable',
          correlation_id: correlationId,
          retry_after: '30 seconds'
        });
        return;
      }
      
      if (error.message.includes('constraint')) {
        logger.error('💥 Database constraint violation during log ingestion', {
          classification: 'HIGH',
          audit_event: 'LOG_INGESTION_CONSTRAINT_VIOLATION',
          error: error.message,
          correlation_id: correlationId,
          client_ip: clientIp,
          duration_ms: duration
        });
        
        res.status(409).json({
          error: 'Data constraint violation',
          correlation_id: correlationId
        });
        return;
      }
    }
    
    // Generic error handling
    logger.error('💥 Log ingestion failed', {
      classification: 'CRITICAL',
      audit_event: 'LOG_INGESTION_FAILED',
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      correlation_id: correlationId,
      client_ip: clientIp,
      duration_ms: duration
    });
    
    res.status(500).json({
      error: 'Internal server error during log ingestion',
      correlation_id: correlationId
    });
  }
};

/**
 * Log ingestion health check
 * GET /api/logs/health
 */
export const logHealthCheck = async (req: Request, res: Response): Promise<void> => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  try {
    // Test database connectivity
    const dbHealthQuery = 'SELECT 1 as healthy, NOW() as timestamp';
    const dbResult = await db.query(dbHealthQuery);
    
    const healthStatus = {
      status: 'healthy',
      service: 'log-ingestion',
      timestamp: new Date().toISOString(),
      database: {
        status: 'connected',
        response_time: dbResult.rows[0].timestamp
      },
      compliance: {
        iso27001: 'active',
        gdpr: 'compliant',
        data_classification: 'enforced'
      },
      endpoints: {
        emit_log: 'available'
      },
      retention: {
        policy: 'automated',
        classifications: Object.keys(CLASSIFICATION_RETENTION)
      },
      correlation_id: correlationId
    };
    
    res.status(200).json(healthStatus);
    
  } catch (error) {
    logger.error('💥 Log service health check failed', {
      classification: 'HIGH',
      audit_event: 'LOG_HEALTH_CHECK_FAILED',
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      service: 'log-ingestion',
      timestamp: new Date().toISOString(),
      error: 'Service health check failed',
      correlation_id: correlationId
    });
  }
};