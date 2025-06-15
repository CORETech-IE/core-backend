/**
 * ?? CORE-BACKEND: Nuclear Metrics Controller
 * 
 * Performance and business metrics ingestion endpoint
 * Supports multi-tenant metric collection with compliance
 * 
 * Classification: CONFIDENTIAL (metrics processing logic)
 * Retention: 90 days (operational metrics)
 * Review Date: Every 3 months (critical component)
 */

import { Request, Response } from 'express';
import { z } from 'zod';
import db from '../../config/db';
import logger from '../../utils/logger';
import nuclearAuditLogger from '../../middlewares/auditLogger';

/**
 * Metric payload validation schema
 * Enforces strict validation for metrics data
 */
const metricPayloadSchema = z.object({
  // ?? Metric identification
  metric_name: z.string()
    .min(1, 'Metric name cannot be empty')
    .max(128, 'Metric name too long')
    .regex(/^[a-zA-Z0-9_.-]+$/, 'Invalid metric name format')
    .trim(),
  
  metric_value: z.number()
    .finite('Metric value must be finite'),
  
  metric_unit: z.string()
    .max(50, 'Metric unit too long')
    .optional(),
  
  // ?? Context
  service: z.string()
    .min(1, 'Service name cannot be empty')
    .max(64, 'Service name too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid service name format')
    .trim(),
  
  tenant_name: z.string()
    .min(1, 'Tenant name cannot be empty')
    .max(64, 'Tenant name too long')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Invalid tenant name format')
    .trim()
    .optional(),
  
  hostname: z.string()
    .max(256, 'Hostname too long')
    .optional(),
  
  // ? Timestamp
  timestamp: z.string()
    .datetime({ message: 'Invalid ISO 8601 timestamp format' })
    .optional()
    .transform(val => val || new Date().toISOString()),
  
  // ??? Dimensions (tags for grouping)
  dimensions: z.record(z.any())
    .optional()
    .default({})
    .refine(
      (obj) => JSON.stringify(obj).length <= 8192, // 8KB limit
      { message: 'Dimensions too large (max 8KB when serialized)' }
    ),
  
  // ?? Additional metadata
  metadata: z.record(z.any())
    .optional()
    .default({})
    .refine(
      (obj) => JSON.stringify(obj).length <= 16384, // 16KB limit
      { message: 'Metadata too large (max 16KB when serialized)' }
    )
});

/**
 * Batch metrics payload schema
 * Allows sending multiple metrics at once
 */
const batchMetricsSchema = z.object({
  metrics: z.array(metricPayloadSchema)
    .min(1, 'At least one metric required')
    .max(1000, 'Maximum 1000 metrics per batch'),
  
  batch_id: z.string()
    .uuid('Invalid UUID format for batch_id')
    .optional()
});

/**
 * Common metric names for validation
 */
const COMMON_METRICS = {
  // System metrics
  'system.cpu.usage': { unit: 'percent', min: 0, max: 100 },
  'system.memory.usage': { unit: 'bytes', min: 0 },
  'system.disk.usage': { unit: 'bytes', min: 0 },
  'system.network.rx': { unit: 'bytes_per_second', min: 0 },
  'system.network.tx': { unit: 'bytes_per_second', min: 0 },
  
  // Application metrics
  'app.request.count': { unit: 'count', min: 0 },
  'app.request.duration': { unit: 'milliseconds', min: 0 },
  'app.error.count': { unit: 'count', min: 0 },
  'app.active.users': { unit: 'count', min: 0 },
  
  // Business metrics
  'business.revenue': { unit: 'currency', min: 0 },
  'business.conversion.rate': { unit: 'percent', min: 0, max: 100 },
  'business.user.signups': { unit: 'count', min: 0 }
};

/**
 * Validate metric value against known metric types
 */
function validateMetricValue(metricName: string, value: number): {
  isValid: boolean;
  error?: string;
} {
  const knownMetric = COMMON_METRICS[metricName as keyof typeof COMMON_METRICS];
  
  if (!knownMetric) {
    // Unknown metric, allow any value
    return { isValid: true };
  }
  
  if (knownMetric.min !== undefined && value < knownMetric.min) {
    return {
      isValid: false,
      error: `${metricName} value must be >= ${knownMetric.min}`
    };
  }
  /*
  if (knownMetric.max !== undefined && value > knownMetric.max) {
    return {
      isValid: false,
      error: `${metricName} value must be <= ${knownMetric.max}`
    };
  }*/
  
  return { isValid: true };
}

/**
 * Store metric in database
 */
async function storeMetric(metric: any, correlationId: string): Promise<any> {
  const insertQuery = `
    INSERT INTO metrics (
      timestamp, metric_name, metric_value, metric_unit,
      service, tenant_name, hostname, dimensions, metadata,
      retention_until, created_at
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9,
      NOW() + INTERVAL '90 days', NOW()
    )
    RETURNING id, created_at, retention_until
  `;
  
  const values = [
    new Date(metric.timestamp),
    metric.metric_name,
    metric.metric_value,
    metric.metric_unit || null,
    metric.service,
    metric.tenant_name || null,
    metric.hostname || null,
    JSON.stringify(metric.dimensions || {}),
    JSON.stringify(metric.metadata || {})
  ];
  
  const result = await db.query(insertQuery, values, correlationId);
  return result.rows[0];
}

/**
 * Nuclear metrics ingestion endpoint
 * POST /api/metrics
 */
export const receiveMetrics = async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();
  const correlationId = (req as any).correlationId || 'unknown';
  const clientIp = req.ip || 'unknown';
  
  try {
    // ?? STEP 1: Determine if batch or single metric
    const isBatch = Array.isArray(req.body.metrics);
    
    logger.info('?? Metrics ingestion started', {
      classification: 'INTERNAL',
      audit_event: 'METRICS_INGESTION_STARTED',
      is_batch: isBatch,
      correlation_id: correlationId,
      client_ip: clientIp
    });
    
    let metricsToProcess: any[] = [];
    let batchId: string | undefined;
    
    // ?? STEP 2: Validate input
    if (isBatch) {
      const batchValidation = batchMetricsSchema.safeParse(req.body);
      
      if (!batchValidation.success) {
        const errors = batchValidation.error.errors;
        
        logger.warn('?? Batch metrics validation failed', {
          classification: 'HIGH',
          audit_event: 'METRICS_VALIDATION_FAILED',
          error_count: errors.length,
          errors: errors.map(e => ({ field: e.path.join('.'), message: e.message })),
          correlation_id: correlationId
        });
        
        res.status(400).json({
          error: 'Invalid metrics batch',
          details: errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          })),
          correlation_id: correlationId
        });
        return;
      }
      
      metricsToProcess = batchValidation.data.metrics;
      batchId = batchValidation.data.batch_id;
    } else {
      // Single metric
      const singleValidation = metricPayloadSchema.safeParse(req.body);
      
      if (!singleValidation.success) {
        const errors = singleValidation.error.errors;
        
        logger.warn('?? Metric validation failed', {
          classification: 'HIGH',
          audit_event: 'METRICS_VALIDATION_FAILED',
          error_count: errors.length,
          errors: errors.map(e => ({ field: e.path.join('.'), message: e.message })),
          correlation_id: correlationId
        });
        
        res.status(400).json({
          error: 'Invalid metric payload',
          details: errors.map(e => ({
            field: e.path.join('.'),
            message: e.message
          })),
          correlation_id: correlationId
        });
        return;
      }
      
      metricsToProcess = [singleValidation.data];
    }
    
    // ??? STEP 3: Validate metric values
    const validationErrors: any[] = [];
    
    for (const metric of metricsToProcess) {
      const valueValidation = validateMetricValue(metric.metric_name, metric.metric_value);
      if (!valueValidation.isValid) {
        validationErrors.push({
          metric_name: metric.metric_name,
          error: valueValidation.error
        });
      }
    }
    
    if (validationErrors.length > 0) {
      res.status(400).json({
        error: 'Invalid metric values',
        details: validationErrors,
        correlation_id: correlationId
      });
      return;
    }
    
    // ??? STEP 4: Store metrics in database
    const results = [];
    const errors = [];
    
    // Use transaction for batch processing
    if (isBatch && metricsToProcess.length > 1) {
      await db.withTransaction(async (client) => {
        for (const metric of metricsToProcess) {
          try {
            const result = await storeMetric(metric, correlationId);
            results.push({
              metric_name: metric.metric_name,
              id: result.id,
              status: 'stored'
            });
          } catch (error) {
            errors.push({
              metric_name: metric.metric_name,
              error: error instanceof Error ? error.message : String(error)
            });
          }
        }
      }, correlationId);
    } else {
      // Single metric, no transaction needed
      try {
        const result = await storeMetric(metricsToProcess[0], correlationId);
        results.push({
          metric_name: metricsToProcess[0].metric_name,
          id: result.id,
          status: 'stored'
        });
      } catch (error) {
        errors.push({
          metric_name: metricsToProcess[0].metric_name,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    
    const duration = Date.now() - startTime;
    
    // ?? STEP 5: Audit logging
    nuclearAuditLogger.logEvent(
      'DATA_CREATED' as any,
      `Metrics ingestion completed`,
      errors.length === 0 ? 'SUCCESS' : 'PARTIAL',
      {
        resource_type: 'metrics',
        resource_id: batchId || results[0]?.id,
        tenant_name: metricsToProcess[0]?.tenant_name,
        metadata: {
          metrics_count: metricsToProcess.length,
          successful_count: results.length,
          failed_count: errors.length,
          is_batch: isBatch,
          batch_id: batchId,
          processing_time_ms: duration
        }
      }
    );
    
    // ?? STEP 6: Response
    const response: any = {
      status: errors.length === 0 ? 'success' : 'partial_success',
      message: `${results.length} metrics stored successfully`,
      correlation_id: correlationId,
      processing_time_ms: duration
    };
    
    if (isBatch) {
      response.batch_id = batchId;
      response.results = results;
      if (errors.length > 0) {
        response.errors = errors;
      }
    } else {
      response.metric_id = results[0]?.id;
    }
    
    res.status(errors.length === 0 ? 201 : 207).json(response);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.error('?? Metrics ingestion failed', {
      classification: 'CRITICAL',
      audit_event: 'METRICS_INGESTION_FAILED',
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      correlation_id: correlationId,
      client_ip: clientIp,
      duration_ms: duration
    });
    
    res.status(500).json({
      error: 'Internal server error during metrics ingestion',
      correlation_id: correlationId
    });
  }
};

/**
 * Get metrics health status
 * GET /api/metrics/health
 */
export const metricsHealthCheck = async (req: Request, res: Response): Promise<void> => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  try {
    // Test database connectivity
    const dbHealthQuery = `
      SELECT 
        COUNT(*) as total_metrics,
        MIN(timestamp) as oldest_metric,
        MAX(timestamp) as newest_metric
      FROM metrics
      WHERE created_at > NOW() - INTERVAL '1 hour'
    `;
    
    const dbResult = await db.query(dbHealthQuery);
    const stats = dbResult.rows[0];
    
    const healthStatus = {
      status: 'healthy',
      service: 'metrics-ingestion',
      timestamp: new Date().toISOString(),
      database: {
        status: 'connected',
        recent_metrics: parseInt(stats.total_metrics),
        oldest_metric: stats.oldest_metric,
        newest_metric: stats.newest_metric
      },
      supported_metrics: Object.keys(COMMON_METRICS),
      endpoints: {
        receive_metrics: 'POST /api/metrics',
        batch_metrics: 'POST /api/metrics (with metrics array)',
        health: 'GET /api/metrics/health'
      },
      limits: {
        max_batch_size: 1000,
        retention_days: 90
      },
      correlation_id: correlationId
    };
    
    res.status(200).json(healthStatus);
    
  } catch (error) {
    logger.error('?? Metrics health check failed', {
      classification: 'HIGH',
      audit_event: 'METRICS_HEALTH_CHECK_FAILED',
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId
    });
    
    res.status(503).json({
      status: 'unhealthy',
      service: 'metrics-ingestion',
      timestamp: new Date().toISOString(),
      error: 'Service health check failed',
      correlation_id: correlationId
    });
  }
};