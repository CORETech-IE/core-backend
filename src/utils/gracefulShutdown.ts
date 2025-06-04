/**
 * 🚨 CORE-BACKEND: Nuclear Graceful Shutdown
 * 
 * Production-ready graceful shutdown for containerized environments
 * Ensures clean termination with audit trail and resource cleanup
 * 
 * Classification: CONFIDENTIAL (system infrastructure)
 * Retention: Service lifetime (operational requirement)
 * Review Date: Every 3 months (critical infrastructure)
 */

import { Server } from 'http';
import logger from './logger';
import db from '../config/db';

/**
 * Shutdown options interface
 */
interface ShutdownOptions {
  timeout?: number;           // Max time to wait for graceful shutdown (ms)
  signals?: string[];         // Signals to handle
  onShutdown?: () => Promise<void>; // Custom cleanup function
  forceExit?: boolean;        // Force exit after timeout
}

/**
 * Shutdown state tracking
 */
interface ShutdownState {
  isShuttingDown: boolean;
  shutdownStartTime: number;
  activeConnections: number;
  shutdownReason: string;
  shutdownInitiator: string;
}

/**
 * Default shutdown configuration
 */
const DEFAULT_OPTIONS: Required<ShutdownOptions> = {
  timeout: 30000,  // 30 seconds
  signals: ['SIGTERM', 'SIGINT', 'SIGUSR2'],
  onShutdown: async () => {},
  forceExit: true
};

/**
 * Global shutdown state
 */
let shutdownState: ShutdownState = {
  isShuttingDown: false,
  shutdownStartTime: 0,
  activeConnections: 0,
  shutdownReason: '',
  shutdownInitiator: ''
};

/**
 * Track active connections for graceful shutdown
 */
function trackConnections(server: Server): void {
  server.on('connection', (socket) => {
    shutdownState.activeConnections++;
    
    socket.on('close', () => {
      shutdownState.activeConnections--;
    });
  });
}

/**
 * Cleanup database connections
 */
async function cleanupDatabase(): Promise<void> {
  try {
    logger.info('🔄 Closing database connections...', {
      classification: 'INTERNAL',
      audit_event: 'DB_SHUTDOWN_STARTED'
    });
    
    await db.shutdown();
    
    logger.info('✅ Database connections closed successfully', {
      classification: 'INTERNAL',
      audit_event: 'DB_SHUTDOWN_COMPLETED'
    });
  } catch (error) {
    logger.error('💥 Error closing database connections', {
      classification: 'HIGH',
      audit_event: 'DB_SHUTDOWN_ERROR',
      error: error instanceof Error ? error.message : String(error)
    });
    
    throw error;
  }
}

/**
 * Close HTTP server gracefully
 */
async function closeServer(server: Server, timeout: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const shutdownTimer = setTimeout(() => {
      logger.warn('⚠️ Server shutdown timeout reached, forcing close', {
        classification: 'HIGH',
        audit_event: 'SERVER_SHUTDOWN_TIMEOUT',
        timeout_ms: timeout,
        active_connections: shutdownState.activeConnections
      });
      
      // Force close all connections
      server.closeAllConnections?.();
      reject(new Error('Server shutdown timeout'));
    }, timeout);
    
    server.close((error) => {
      clearTimeout(shutdownTimer);
      
      if (error) {
        logger.error('💥 Error closing HTTP server', {
          classification: 'HIGH',
          audit_event: 'SERVER_SHUTDOWN_ERROR',
          error: error.message
        });
        reject(error);
      } else {
        logger.info('✅ HTTP server closed successfully', {
          classification: 'INTERNAL',
          audit_event: 'SERVER_SHUTDOWN_COMPLETED'
        });
        resolve();
      }
    });
    
    // Stop accepting new connections
    logger.info('🔄 Stopping new connections...', {
      classification: 'INTERNAL',
      audit_event: 'SERVER_STOP_NEW_CONNECTIONS'
    });
  });
}

/**
 * Perform comprehensive cleanup
 */
async function performCleanup(options: Required<ShutdownOptions>): Promise<void> {
  const cleanupStartTime = Date.now();
  
  try {
    logger.info('🧹 Starting application cleanup...', {
      classification: 'INTERNAL',
      audit_event: 'CLEANUP_STARTED',
      shutdown_reason: shutdownState.shutdownReason
    });
    
    // Execute custom cleanup function
    if (options.onShutdown) {
      logger.info('🔄 Executing custom cleanup...', {
        classification: 'INTERNAL',
        audit_event: 'CUSTOM_CLEANUP_STARTED'
      });
      
      await options.onShutdown();
      
      logger.info('✅ Custom cleanup completed', {
        classification: 'INTERNAL',
        audit_event: 'CUSTOM_CLEANUP_COMPLETED'
      });
    }
    
    // Cleanup database connections
    await cleanupDatabase();
    
    const cleanupDuration = Date.now() - cleanupStartTime;
    
    logger.info('✅ Application cleanup completed successfully', {
      classification: 'INTERNAL',
      audit_event: 'CLEANUP_COMPLETED',
      cleanup_duration_ms: cleanupDuration
    });
    
  } catch (error) {
    const cleanupDuration = Date.now() - cleanupStartTime;
    
    logger.error('💥 Error during application cleanup', {
      classification: 'CRITICAL',
      audit_event: 'CLEANUP_ERROR',
      error: error instanceof Error ? error.message : String(error),
      cleanup_duration_ms: cleanupDuration
    });
    
    throw error;
  }
}

/**
 * Log final shutdown statistics
 */
function logShutdownStats(): void {
  const shutdownDuration = Date.now() - shutdownState.shutdownStartTime;
  
  logger.info('📊 Shutdown statistics', {
    classification: 'INTERNAL',
    audit_event: 'SHUTDOWN_STATISTICS',
    shutdown_reason: shutdownState.shutdownReason,
    shutdown_initiator: shutdownState.shutdownInitiator,
    total_duration_ms: shutdownDuration,
    process_uptime_seconds: Math.floor(process.uptime()),
    process_pid: process.pid,
    memory_usage: process.memoryUsage(),
    final_active_connections: shutdownState.activeConnections
  });
}

/**
 * Execute graceful shutdown sequence
 */
async function executeShutdown(
  server: Server,
  reason: string,
  initiator: string,
  options: Required<ShutdownOptions>
): Promise<void> {
  
  // Prevent multiple shutdown attempts
  if (shutdownState.isShuttingDown) {
    logger.warn('⚠️ Shutdown already in progress, ignoring duplicate signal', {
      classification: 'INTERNAL',
      audit_event: 'DUPLICATE_SHUTDOWN_SIGNAL',
      reason,
      initiator
    });
    return;
  }
  
  // Initialize shutdown state
  shutdownState.isShuttingDown = true;
  shutdownState.shutdownStartTime = Date.now();
  shutdownState.shutdownReason = reason;
  shutdownState.shutdownInitiator = initiator;
  
  logger.info('🔄 Graceful shutdown initiated', {
    classification: 'HIGH',
    audit_event: 'SHUTDOWN_INITIATED',
    reason,
    initiator,
    process_pid: process.pid,
    active_connections: shutdownState.activeConnections,
    timeout_ms: options.timeout
  });
  
  try {
    // Set up force exit timeout
    const forceExitTimer = setTimeout(() => {
      logger.error('💥 CRITICAL: Graceful shutdown timeout, forcing exit', {
        classification: 'CRITICAL',
        audit_event: 'SHUTDOWN_FORCE_EXIT',
        timeout_ms: options.timeout,
        shutdown_duration_ms: Date.now() - shutdownState.shutdownStartTime
      });
      
      logShutdownStats();
      process.exit(1);
    }, options.timeout);
    
    // Close HTTP server
    await closeServer(server, options.timeout - 5000); // Reserve 5s for cleanup
    
    // Perform application cleanup
    await performCleanup(options);
    
    // Clear force exit timer
    clearTimeout(forceExitTimer);
    
    // Log successful shutdown
    logger.info('✅ Graceful shutdown completed successfully', {
      classification: 'HIGH',
      audit_event: 'SHUTDOWN_COMPLETED',
      shutdown_duration_ms: Date.now() - shutdownState.shutdownStartTime
    });
    
    logShutdownStats();
    
    // Exit gracefully
    if (options.forceExit) {
      process.exit(0);
    }
    
  } catch (error) {
    logger.error('💥 CRITICAL: Graceful shutdown failed', {
      classification: 'CRITICAL',
      audit_event: 'SHUTDOWN_FAILED',
      error: error instanceof Error ? error.message : String(error),
      shutdown_duration_ms: Date.now() - shutdownState.shutdownStartTime
    });
    
    logShutdownStats();
    
    // Force exit on failure
    if (options.forceExit) {
      process.exit(1);
    }
  }
}

/**
 * Setup graceful shutdown handlers
 */
export function gracefulShutdown(
  server: Server,
  userOptions: Partial<ShutdownOptions> = {}
): (reason: string) => void {
  
  const options = { ...DEFAULT_OPTIONS, ...userOptions };
  
  // Track server connections
  trackConnections(server);
  
  // Log initialization
  logger.info('🛡️ Graceful shutdown handlers initialized', {
    classification: 'INTERNAL',
    audit_event: 'SHUTDOWN_HANDLERS_INITIALIZED',
    signals: options.signals,
    timeout_ms: options.timeout,
    force_exit: options.forceExit
  });
  
  // Create shutdown function
  const shutdown = (reason: string) => {
    executeShutdown(server, reason, 'manual', options);
  };
  
  // Setup signal handlers
  options.signals.forEach(signal => {
    process.on(signal, () => {
      executeShutdown(server, `Signal: ${signal}`, 'system', options);
    });
  });
  
  // Handle uncaught exceptions
  process.on('uncaughtException', (error) => {
    logger.error('💥 CRITICAL: Uncaught exception', {
      classification: 'CRITICAL',
      audit_event: 'UNCAUGHT_EXCEPTION',
      error: error.message,
      stack: error.stack
    });
    
    executeShutdown(server, 'Uncaught Exception', 'system', options);
  });
  
  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('💥 CRITICAL: Unhandled promise rejection', {
      classification: 'CRITICAL',
      audit_event: 'UNHANDLED_REJECTION',
      reason: String(reason),
      promise: String(promise)
    });
    
    executeShutdown(server, 'Unhandled Promise Rejection', 'system', options);
  });
  
  return shutdown;
}

/**
 * Check if shutdown is in progress
 */
export function isShuttingDown(): boolean {
  return shutdownState.isShuttingDown;
}

/**
 * Get current shutdown state
 */
export function getShutdownState(): Readonly<ShutdownState> {
  return { ...shutdownState };
}

export default gracefulShutdown;