/**
 * 🚨 CORE-BACKEND: Nuclear Database Configuration
 * 
 * Production-ready PostgreSQL connection pool with comprehensive monitoring
 * Implements security, reliability, and compliance controls
 * 
 * Classification: CONFIDENTIAL (database connection logic)
 * Retention: Service lifetime (operational requirement)
 * Review Date: Every 3 months (critical infrastructure)
 */

import { Pool, PoolClient, QueryResult, PoolConfig, QueryResultRow } from 'pg';
import envConfig from './envConfig';
import logger from '../utils/logger';

/**
 * Database query interface for type safety
 */
interface DatabaseQuery {
  text: string;
  values?: any[];
  name?: string; // For prepared statements
}

/**
 * Database health status interface
 */
interface DatabaseHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  connections: {
    total: number;
    idle: number;
    waiting: number;
  };
  latency_ms: number;
  last_error?: string;
  uptime_seconds: number;
}

/**
 * Nuclear PostgreSQL configuration
 * Optimized for production workloads with security controls
 */
const poolConfig: PoolConfig = {
  // Connection parameters from environment
  host: envConfig.pgHost,
  port: envConfig.pgPort,
  database: envConfig.pgDatabase,
  user: envConfig.pgUser,
  password: envConfig.pgPassword,
  
  // Connection pool configuration
  min: 2,                    // Minimum connections (always ready)
  max: 20,                   // Maximum connections (prevent resource exhaustion)
  idleTimeoutMillis: 30000,  // 30 seconds idle timeout
  connectionTimeoutMillis: 5000, // 5 seconds connection timeout
  
  // SSL configuration (production security)
  ssl: envConfig.nodeEnv === 'production' ? {
    rejectUnauthorized: true,
    ca: process.env.POSTGRES_CA_CERT,
    cert: process.env.POSTGRES_CLIENT_CERT,
    key: process.env.POSTGRES_CLIENT_KEY
  } : false,
  
  // Application identification
  application_name: `${envConfig.serviceName}-${envConfig.nodeEnv}`,
  
  // Connection validation
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
  
  // Performance tuning
  allowExitOnIdle: false     // Keep process alive
};

/**
 * Nuclear PostgreSQL connection pool
 */
const pool = new Pool(poolConfig);

/**
 * Pool monitoring and health tracking
 */
let poolStartTime = Date.now();
let lastHealthCheck = 0;
let cachedHealth: DatabaseHealth | null = null;
const HEALTH_CACHE_TTL = 5000; // 5 seconds

/**
 * Pool event handlers for comprehensive monitoring
 */
pool.on('connect', (client: PoolClient) => {
  logger.info('📊 Database connection established', {
    classification: 'INTERNAL',
    audit_event: 'DB_CONNECTION_ESTABLISHED',
    total_connections: pool.totalCount,
    idle_connections: pool.idleCount,
    waiting_connections: pool.waitingCount
  });
});

pool.on('acquire', (client: PoolClient) => {
  logger.debug('🔗 Database connection acquired', {
    classification: 'INTERNAL',
    audit_event: 'DB_CONNECTION_ACQUIRED',
    total_connections: pool.totalCount,
    idle_connections: pool.idleCount
  });
});

pool.on('release', (err: Error | undefined, client: PoolClient) => {
  if (err) {
    logger.error('💥 Database connection released with error', {
      classification: 'HIGH',
      audit_event: 'DB_CONNECTION_ERROR_RELEASE',
      error: err.message,
      stack: err.stack
    });
  } else {
    logger.debug('✅ Database connection released', {
      classification: 'INTERNAL',
      audit_event: 'DB_CONNECTION_RELEASED',
      idle_connections: pool.idleCount
    });
  }
});

pool.on('remove', (client: PoolClient) => {
  logger.warn('🗑️ Database connection removed from pool', {
    classification: 'INTERNAL',
    audit_event: 'DB_CONNECTION_REMOVED',
    total_connections: pool.totalCount,
    reason: 'Connection exceeded lifetime or failed validation'
  });
});

pool.on('error', (err: Error, client: PoolClient) => {
  logger.error('💥 CRITICAL: Database pool error', {
    classification: 'CRITICAL',
    audit_event: 'DB_POOL_ERROR',
    error: err.message,
    stack: err.stack,
    total_connections: pool.totalCount,
    idle_connections: pool.idleCount
  });
});

/**
 * Enhanced query execution with comprehensive logging and error handling
 */
async function executeQuery<T extends QueryResultRow = any>(
  queryInput: string | DatabaseQuery,
  params?: any[],
  correlationId?: string
): Promise<QueryResult<T>> {
  const startTime = Date.now();
  const cid = correlationId || generateCorrelationId();
  
  // Normalize query input
  const query = typeof queryInput === 'string' 
    ? { text: queryInput, values: params }
    : queryInput;
  
  // Sanitize query for logging (remove sensitive data)
  const sanitizedQuery = sanitizeQueryForLogging(query.text);
  
  logger.debug('🔍 Database query started', {
    classification: 'INTERNAL',
    audit_event: 'DB_QUERY_STARTED',
    query_type: getQueryType(query.text),
    query_hash: hashQuery(query.text),
    param_count: query.values?.length || 0,
    correlation_id: cid,
    pool_stats: {
      total: pool.totalCount,
      idle: pool.idleCount,
      waiting: pool.waitingCount
    }
  });
  
  try {
    const result = await pool.query<T>(query);
    const duration = Date.now() - startTime;
    
    logger.info('✅ Database query completed', {
      classification: 'INTERNAL',
      audit_event: 'DB_QUERY_COMPLETED',
      query_type: getQueryType(query.text),
      query_hash: hashQuery(query.text),
      rows_affected: result.rowCount,
      rows_returned: result.rows.length,
      duration_ms: duration,
      correlation_id: cid
    });
    
    // Log slow queries for performance monitoring
    if (duration > 1000) { // Queries over 1 second
      logger.warn('🐌 Slow database query detected', {
        classification: 'INTERNAL',
        audit_event: 'DB_SLOW_QUERY',
        query_type: getQueryType(query.text),
        duration_ms: duration,
        sanitized_query: sanitizedQuery,
        correlation_id: cid
      });
    }
    
    return result;
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    logger.error('💥 Database query failed', {
      classification: 'HIGH',
      audit_event: 'DB_QUERY_FAILED',
      query_type: getQueryType(query.text),
      query_hash: hashQuery(query.text),
      error: error instanceof Error ? error.message : String(error),
      duration_ms: duration,
      correlation_id: cid,
      sanitized_query: sanitizedQuery
    });
    
    // Re-throw with additional context
    const enhancedError = new Error(`Database query failed: ${error instanceof Error ? error.message : String(error)}`);
    (enhancedError as any).originalError = error;
    (enhancedError as any).correlationId = cid;
    (enhancedError as any).queryType = getQueryType(query.text);
    
    throw enhancedError;
  }
}

/**
 * Database health check with comprehensive monitoring
 */
async function getHealth(): Promise<DatabaseHealth> {
  const now = Date.now();
  
  // Use cached health if recent
  if (cachedHealth && (now - lastHealthCheck) < HEALTH_CACHE_TTL) {
    return cachedHealth;
  }
  
  const healthCheckStart = Date.now();
  
  try {
    // Simple connectivity test
    await pool.query('SELECT 1 as health_check, NOW() as server_time');
    
    const latency = Date.now() - healthCheckStart;
    const uptime = Math.floor((now - poolStartTime) / 1000);
    
    cachedHealth = {
      status: latency > 5000 ? 'degraded' : 'healthy',
      connections: {
        total: pool.totalCount,
        idle: pool.idleCount,
        waiting: pool.waitingCount
      },
      latency_ms: latency,
      uptime_seconds: uptime
    };
    
    lastHealthCheck = now;
    
    logger.debug('💗 Database health check completed', {
      classification: 'INTERNAL',
      audit_event: 'DB_HEALTH_CHECK_SUCCESS',
      status: cachedHealth.status,
      latency_ms: latency,
      connections: cachedHealth.connections
    });
    
    return cachedHealth;
    
  } catch (error) {
    const latency = Date.now() - healthCheckStart;
    
    cachedHealth = {
      status: 'unhealthy',
      connections: {
        total: pool.totalCount,
        idle: pool.idleCount,
        waiting: pool.waitingCount
      },
      latency_ms: latency,
      last_error: error instanceof Error ? error.message : String(error),
      uptime_seconds: Math.floor((now - poolStartTime) / 1000)
    };
    
    lastHealthCheck = now;
    
    logger.error('💥 Database health check failed', {
      classification: 'CRITICAL',
      audit_event: 'DB_HEALTH_CHECK_FAILED',
      error: error instanceof Error ? error.message : String(error),
      latency_ms: latency,
      connections: cachedHealth.connections
    });
    
    return cachedHealth;
  }
}

/**
 * Transaction wrapper with automatic rollback
 */
async function withTransaction<T>(
  callback: (client: PoolClient) => Promise<T>,
  correlationId?: string
): Promise<T> {
  const cid = correlationId || generateCorrelationId();
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    logger.debug('🔄 Database transaction started', {
      classification: 'INTERNAL',
      audit_event: 'DB_TRANSACTION_STARTED',
      correlation_id: cid
    });
    
    const result = await callback(client);
    
    await client.query('COMMIT');
    
    logger.info('✅ Database transaction committed', {
      classification: 'INTERNAL',
      audit_event: 'DB_TRANSACTION_COMMITTED',
      correlation_id: cid
    });
    
    return result;
    
  } catch (error) {
    await client.query('ROLLBACK');
    
    logger.error('💥 Database transaction rolled back', {
      classification: 'HIGH',
      audit_event: 'DB_TRANSACTION_ROLLBACK',
      error: error instanceof Error ? error.message : String(error),
      correlation_id: cid
    });
    
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Graceful pool shutdown
 */
async function shutdown(): Promise<void> {
  logger.info('🔄 Database pool shutdown initiated', {
    classification: 'INTERNAL',
    audit_event: 'DB_POOL_SHUTDOWN_STARTED'
  });
  
  try {
    await pool.end();
    
    logger.info('✅ Database pool shutdown completed', {
      classification: 'INTERNAL',
      audit_event: 'DB_POOL_SHUTDOWN_COMPLETED'
    });
  } catch (error) {
    logger.error('💥 Database pool shutdown error', {
      classification: 'HIGH',
      audit_event: 'DB_POOL_SHUTDOWN_ERROR',
      error: error instanceof Error ? error.message : String(error)
    });
    
    throw error;
  }
}

/**
 * Utility functions
 */
function generateCorrelationId(): string {
  return `db-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 8)}`;
}

function getQueryType(query: string): string {
  const upperQuery = query.trim().toUpperCase();
  if (upperQuery.startsWith('SELECT')) return 'SELECT';
  if (upperQuery.startsWith('INSERT')) return 'INSERT';
  if (upperQuery.startsWith('UPDATE')) return 'UPDATE';
  if (upperQuery.startsWith('DELETE')) return 'DELETE';
  if (upperQuery.startsWith('CREATE')) return 'CREATE';
  if (upperQuery.startsWith('ALTER')) return 'ALTER';
  if (upperQuery.startsWith('DROP')) return 'DROP';
  return 'OTHER';
}

function hashQuery(query: string): string {
  // Simple hash for query identification (not cryptographic)
  let hash = 0;
  for (let i = 0; i < query.length; i++) {
    const char = query.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(36);
}

function sanitizeQueryForLogging(query: string): string {
  // Remove potential sensitive data for logging
  return query
    .replace(/password\s*=\s*'[^']+'/gi, "password='[REDACTED]'")
    .replace(/token\s*=\s*'[^']+'/gi, "token='[REDACTED]'")
    .replace(/secret\s*=\s*'[^']+'/gi, "secret='[REDACTED]'")
    .substring(0, 200); // Limit length
}

// Initialize pool monitoring
logger.info('🗄️ Nuclear database pool initialized', {
  classification: 'INTERNAL',
  audit_event: 'DB_POOL_INITIALIZED',
  config: {
    host: envConfig.pgHost,
    database: envConfig.pgDatabase,
    user: envConfig.pgUser,
    min_connections: poolConfig.min,
    max_connections: poolConfig.max,
    ssl_enabled: !!poolConfig.ssl,
    application_name: poolConfig.application_name
  }
});

/**
 * Nuclear database interface
 * Provides comprehensive database operations with monitoring
 */
export default {
  // Core query interface (backward compatible)
  query: executeQuery,
  
  // Enhanced interfaces
  executeQuery,
  withTransaction,
  getHealth,
  shutdown,
  
  // Pool access for advanced operations
  pool,
  
  // Utility functions
  generateCorrelationId
};