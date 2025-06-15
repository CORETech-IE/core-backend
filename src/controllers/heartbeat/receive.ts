/**
 * ?? CORE-BACKEND: Heartbeat Controller
 * 
 * Service health monitoring endpoint
 * Tracks service status and health metrics
 */

import { Request, Response } from 'express';
import { z } from 'zod';
import db from '../../config/db';
import logger from '../../utils/logger';
import envConfig from '../../config/envConfig';

/**
 * Heartbeat payload validation schema
 */
const heartbeatSchema = z.object({
  client_id: z.string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9_-]+$/),
  
  service: z.string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9_-]+$/),
  
  hostname: z.string()
    .max(256)
    .optional(),
  
  status: z.enum(['OK', 'STARTUP', 'WARNING', 'ERROR', 'SHUTDOWN'])
    .default('OK'),
  
  // Health metrics
  uptime_seconds: z.number()
    .int()
    .min(0)
    .optional(),
  
  memory_usage_mb: z.number()
    .int()
    .min(0)
    .optional(),
  
  cpu_usage_percent: z.number()
    .min(0)
    .max(100)
    .optional(),
  
  active_connections: z.number()
    .int()
    .min(0)
    .optional(),
  
  // Additional metadata
  metadata: z.record(z.any())
    .optional()
    .default({})
});

/**
 * Send heartbeat
 * POST /api/heartbeat
 */
export const sendHeartbeat = async (req: Request, res: Response): Promise<void> => {
  const startTime = Date.now();
  const correlationId = (req as any).correlationId || 'unknown';
  
  try {
    // Validate payload
    const validationResult = heartbeatSchema.safeParse(req.body);
    
    if (!validationResult.success) {
      const errors = validationResult.error.errors;
      
      logger.warn('Heartbeat validation failed', {
        error_count: errors.length,
        errors: errors.map(e => ({ field: e.path.join('.'), message: e.message })),
        correlation_id: correlationId
      });
      
      res.status(400).json({
        error: 'Invalid heartbeat payload',
        details: errors.map(e => ({
          field: e.path.join('.'),
          message: e.message
        })),
        correlation_id: correlationId
      });
      return;
    }
    
    const heartbeat = validationResult.data;
    
    // Calculate process uptime if not provided
    if (!heartbeat.uptime_seconds) {
      heartbeat.uptime_seconds = Math.floor(process.uptime());
    }
    
    // Get memory usage if not provided
    if (!heartbeat.memory_usage_mb) {
      const memUsage = process.memoryUsage();
      heartbeat.memory_usage_mb = Math.round(memUsage.heapUsed / 1024 / 1024);
    }
    
    // Insert heartbeat
    const insertQuery = `
      INSERT INTO core_dev.heartbeats (
        client_id, service, hostname, timestamp, status,
        uptime_seconds, memory_usage_mb, cpu_usage_percent, 
        active_connections, metadata, retention_until
      ) VALUES (
        $1, $2, $3, NOW(), $4, $5, $6, $7, $8, $9,
        NOW() + INTERVAL '7 days'
      )
      RETURNING id, timestamp
    `;
    
    const values = [
      heartbeat.client_id,
      heartbeat.service,
      heartbeat.hostname || require('os').hostname(),
      heartbeat.status,
      heartbeat.uptime_seconds,
      heartbeat.memory_usage_mb,
      heartbeat.cpu_usage_percent || null,
      heartbeat.active_connections || null,
      JSON.stringify(heartbeat.metadata)
    ];
    
    const result = await db.query(insertQuery, values, correlationId);
    const inserted = result.rows[0];
    
    const duration = Date.now() - startTime;
    
    logger.info('?? Heartbeat recorded', {
      heartbeat_id: inserted.id,
      client_id: heartbeat.client_id,
      service: heartbeat.service,
      status: heartbeat.status,
      duration_ms: duration,
      correlation_id: correlationId
    });
    
    res.status(201).json({
      status: 'success',
      message: 'Heartbeat recorded',
      heartbeat_id: inserted.id,
      timestamp: inserted.timestamp,
      correlation_id: correlationId,
      processing_time_ms: duration
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.error('Heartbeat recording failed', {
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId,
      duration_ms: duration
    });
    
    res.status(500).json({
      error: 'Failed to record heartbeat',
      correlation_id: correlationId
    });
  }
};

/**
 * Get service status
 * GET /api/heartbeat/:service
 */
export const getServiceStatus = async (req: Request, res: Response): Promise<void> => {
  const { service } = req.params;
  const correlationId = (req as any).correlationId || 'unknown';
  
  try {
    const query = `
      SELECT 
        client_id,
        service,
        hostname,
        timestamp,
        status,
        uptime_seconds,
        memory_usage_mb,
        cpu_usage_percent,
        active_connections,
        metadata
      FROM core_dev.heartbeats
      WHERE service = $1
      ORDER BY timestamp DESC
      LIMIT 10
    `;
    
    const result = await db.query(query, [service], correlationId);
    
    // Get latest status
    const latest = result.rows[0];
    const isHealthy = latest && 
      ['OK', 'STARTUP'].includes(latest.status) && 
      (Date.now() - new Date(latest.timestamp).getTime()) < 300000; // 5 min
    
    res.status(200).json({
      service,
      healthy: isHealthy,
      latest_heartbeat: latest || null,
      recent_heartbeats: result.rows,
      correlation_id: correlationId
    });
    
  } catch (error) {
    logger.error('Failed to get service status', {
      error: error instanceof Error ? error.message : String(error),
      service,
      correlation_id: correlationId
    });
    
    res.status(500).json({
      error: 'Failed to get service status',
      correlation_id: correlationId
    });
  }
};

/**
 * Get all services status
 * GET /api/heartbeat
 */
export const getAllServicesStatus = async (req: Request, res: Response): Promise<void> => {
  const correlationId = (req as any).correlationId || 'unknown';
  
  try {
    const query = `
      WITH latest_heartbeats AS (
        SELECT DISTINCT ON (service) 
          client_id,
          service,
          hostname,
          timestamp,
          status,
          uptime_seconds,
          memory_usage_mb
        FROM core_dev.heartbeats
        WHERE timestamp > NOW() - INTERVAL '10 minutes'
        ORDER BY service, timestamp DESC
      )
      SELECT * FROM latest_heartbeats
      ORDER BY service
    `;
    
    const result = await db.query(query, [], correlationId);
    
    const services = result.rows.map(row => ({
      ...row,
      healthy: ['OK', 'STARTUP'].includes(row.status)
    }));
    
    res.status(200).json({
      status: 'success',
      total_services: services.length,
      healthy_services: services.filter(s => s.healthy).length,
      services,
      correlation_id: correlationId
    });
    
  } catch (error) {
    logger.error('Failed to get all services status', {
      error: error instanceof Error ? error.message : String(error),
      correlation_id: correlationId
    });
    
    res.status(500).json({
      error: 'Failed to get services status',
      correlation_id: correlationId
    });
  }
};