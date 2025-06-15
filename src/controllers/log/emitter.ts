/**
 * ?? CORE-BACKEND: Log Emitter Controller
 * 
 * Test endpoint for generating sample logs
 * Useful for testing log ingestion and demo purposes
 * 
 * Classification: INTERNAL (testing functionality)
 * Retention: Not applicable (test endpoint)
 * Review Date: Every 6 months
 */

import { Request, Response } from 'express';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import envConfig from '../../config/envConfig';
import logger from '../../utils/logger';

/**
 * Sample log templates for different scenarios
 */
const LOG_TEMPLATES = {
  auth: [
    { level: 'info', message: 'User authentication successful', classification: 'internal' },
    { level: 'warn', message: 'Failed login attempt detected', classification: 'confidential' },
    { level: 'error', message: 'Authentication service unavailable', classification: 'internal' }
  ],
  api: [
    { level: 'info', message: 'API request processed successfully', classification: 'public' },
    { level: 'warn', message: 'API rate limit approaching threshold', classification: 'internal' },
    { level: 'error', message: 'API endpoint returned 5xx error', classification: 'internal' }
  ],
  database: [
    { level: 'info', message: 'Database query executed successfully', classification: 'internal' },
    { level: 'warn', message: 'Database connection pool near capacity', classification: 'internal' },
    { level: 'error', message: 'Database transaction failed', classification: 'confidential' }
  ],
  security: [
    { level: 'warn', message: 'Suspicious activity detected from IP', classification: 'confidential' },
    { level: 'error', message: 'Potential SQL injection attempt blocked', classification: 'restricted' },
    { level: 'critical', message: 'Multiple failed authentication attempts', classification: 'restricted' }
  ],
  business: [
    { level: 'info', message: 'New user registration completed', classification: 'internal' },
    { level: 'info', message: 'Payment processed successfully', classification: 'confidential' },
    { level: 'error', message: 'Payment gateway timeout', classification: 'confidential' }
  ]
};

/**
 * Services that might emit logs
 */
const SERVICES = [
  'auth-service',
  'api-gateway',
  'payment-service',
  'user-service',
  'notification-service',
  'analytics-service',
  'report-service'
];

/**
 * Generate random log data
 */
function generateRandomLog(category?: string) {
  const categories = Object.keys(LOG_TEMPLATES);
  const selectedCategory = category || categories[Math.floor(Math.random() * categories.length)];
  const templates = LOG_TEMPLATES[selectedCategory as keyof typeof LOG_TEMPLATES];
  const template = templates[Math.floor(Math.random() * templates.length)];
  const service = SERVICES[Math.floor(Math.random() * SERVICES.length)];
  
  return {
    tenant_name: envConfig.tenantId || 'core-dev',
    service,
    level: template.level,
    message: template.message,
    classification: template.classification,
    trace_id: uuidv4(),
    timestamp: new Date().toISOString(),
    tags: [selectedCategory, service, template.level],
    context: {
      category: selectedCategory,
      environment: envConfig.nodeEnv,
      host: envConfig.backendHost,
      random_value: Math.floor(Math.random() * 1000),
      user_id: `user-${Math.floor(Math.random() * 10000)}`,
      session_id: uuidv4(),
      ip_address: `192.168.1.${Math.floor(Math.random() * 255)}`
    }
  };
}

/**
 * Send log to the ingestion endpoint
 */
async function sendLogToEndpoint(logData: any, authToken?: string): Promise<any> {
  const url = `http://localhost:${envConfig.backendPort}/api/emit-log`;
  
  const headers: any = {
    'Content-Type': 'application/json',
    'X-Trace-ID': logData.trace_id
  };
  
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  
  const response = await axios.post(url, logData, { headers });
  return response.data;
}

/**
 * Generate and emit test logs
 * POST /emit-log (for backward compatibility with appRoutes.ts)
 * 
 * This endpoint generates sample logs and sends them to the actual log ingestion endpoint
 */
export const generateLogEmitter = async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();
  const correlationId = (req as any).correlationId || uuidv4();
  
  try {
    // Extract parameters from request
    const {
      count = 1,
      category,
      burst = false,
      includeErrors = false,
      delayMs = 0
    } = req.body || {};
    
    // Validate count
    if (count < 1 || count > 100) {
      res.status(400).json({
        error: 'Count must be between 1 and 100',
        correlation_id: correlationId
      });
      return;
    }
    
    logger.info('?? Test log generation started', {
      classification: 'INTERNAL',
      audit_event: 'TEST_LOG_GENERATION',
      count,
      category,
      burst,
      correlation_id: correlationId
    });
    
    const results = [];
    const errors = [];
    
    // Get auth token from current request
    const authToken = req.headers.authorization?.replace('Bearer ', '');
    
    // Generate and send logs
    for (let i = 0; i < count; i++) {
      try {
        // Generate log data
        const logData = generateRandomLog(category);
        
        // Add error logs if requested
        if (includeErrors && i % 3 === 0) {
          logData.level = 'error';
          logData.message = `Simulated error #${i}: ${logData.message}`;
        }
        
        // Add delay between logs if not burst mode
        if (!burst && delayMs > 0 && i > 0) {
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
        
        // Send to actual log ingestion endpoint
        const result = await sendLogToEndpoint(logData, authToken);
        
        results.push({
          index: i,
          log_id: result.log_id,
          trace_id: logData.trace_id,
          level: logData.level,
          service: logData.service
        });
        
      } catch (error) {
        errors.push({
          index: i,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    
    const duration = Date.now() - startTime;
    
    // Prepare response
    const response: any = {
      status: errors.length === 0 ? 'success' : 'partial_success',
      message: `Generated and sent ${results.length} test logs`,
      correlation_id: correlationId,
      processing_time_ms: duration,
      results: {
        total_requested: count,
        successful: results.length,
        failed: errors.length
      }
    };
    
    if (results.length > 0) {
      response.sample_results = results.slice(0, 5); // First 5 results
    }
    
    if (errors.length > 0) {
      response.errors = errors;
    }
    
    res.status(errors.length === 0 ? 200 : 207).json(response);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.error('?? Test log generation failed', {
      classification: 'HIGH',
      audit_event: 'TEST_LOG_GENERATION_FAILED',
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId,
      duration_ms: duration
    });
    
    res.status(500).json({
      error: 'Failed to generate test logs',
      details: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId
    });
  }
};

/**
 * Generate burst of logs for load testing
 * POST /api/logs/burst
 */
export const generateLogBurst = async (req: Request, res: Response): Promise<void> => {
  const correlationId = (req as any).correlationId || uuidv4();
  
  try {
    const {
      total = 1000,
      batchSize = 100,
      delayBetweenBatches = 1000
    } = req.body || {};
    
    logger.info('?? Log burst generation started', {
      classification: 'INTERNAL',
      audit_event: 'LOG_BURST_STARTED',
      total,
      batchSize,
      correlation_id: correlationId
    });
    
    const batches = Math.ceil(total / batchSize);
    let totalSent = 0;
    let totalErrors = 0;
    
    for (let batch = 0; batch < batches; batch++) {
      const logsInBatch = Math.min(batchSize, total - totalSent);
      
      // Generate batch
      const logs = [];
      for (let i = 0; i < logsInBatch; i++) {
        logs.push(generateRandomLog());
      }
      
      // Send batch (you might want to implement actual batch sending)
      try {
        // This is simplified - in reality you'd send these in parallel or use a batch endpoint
        const authToken = req.headers.authorization?.replace('Bearer ', '');
        for (const log of logs) {
          await sendLogToEndpoint(log, authToken);
          totalSent++;
        }
      } catch (error) {
        totalErrors++;
      }
      
      // Delay between batches
      if (batch < batches - 1) {
        await new Promise(resolve => setTimeout(resolve, delayBetweenBatches));
      }
    }
    
    res.status(200).json({
      status: 'completed',
      message: `Burst generation completed`,
      correlation_id: correlationId,
      results: {
        total_requested: total,
        total_sent: totalSent,
        total_errors: totalErrors,
        batches_processed: batches
      }
    });
    
  } catch (error) {
    logger.error('?? Log burst generation failed', {
      classification: 'HIGH',
      audit_event: 'LOG_BURST_FAILED',
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId
    });
    
    res.status(500).json({
      error: 'Failed to generate log burst',
      correlation_id: correlationId
    });
  }
};

/**
 * Get available log templates
 * GET /api/logs/templates
 */
export const getLogTemplates = async (req: Request, res: Response): Promise<void> => {
  res.status(200).json({
    status: 'success',
    templates: LOG_TEMPLATES,
    categories: Object.keys(LOG_TEMPLATES),
    services: SERVICES,
    usage: {
      single_log: 'POST /emit-log { count: 1, category: "auth" }',
      multiple_logs: 'POST /emit-log { count: 10, delayMs: 100 }',
      burst_mode: 'POST /emit-log { count: 50, burst: true }',
      with_errors: 'POST /emit-log { count: 20, includeErrors: true }'
    }
  });
};