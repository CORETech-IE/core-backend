/**
 * 🚨 CORE-BACKEND: Nuclear Log Ingestion Service
 * 
 * Single Responsibility: Log ingestion endpoint ONLY
 * Compliance: Zero Trust + ISO 27001 + GDPR by design
 * Architecture: Auditor-proof, drunk monkey deployable
 * 
 * Classification: CONFIDENTIAL (ISO 27001 A.8.2.1)
 * Retention: 7 years (compliance requirement)
 * Review Date: Every 6 months
 */

import express from 'express';
import { Server } from 'http';
import dotenv from 'dotenv';

// Load environment variables first
dotenv.config();

// Core imports
import { validateConfig } from './config/config-validator';
import { validateCompliance } from './config/compliance-validator';
import configureExpress from './config/express';
import authRoutes from './routes/authRoutes';
import logRoutes from './routes/logRoutes';
import { errorHandler } from './middlewares/errorHandler';
import { auditLoggerMiddleware } from './middlewares/auditLogger';
import nuclearAuditLogger from './middlewares/auditLogger';
import { gracefulShutdown } from './utils/gracefulShutdown';
import { startRetentionService } from './services/retentionService';
import logger from './utils/logger';

/**
 * Nuclear startup sequence
 * Each step is critical for compliance and security
 */
async function startNuclearService(): Promise<Server> {
  try {
    // 🔍 STEP 1: Configuration validation (fail-fast)
    logger.info('🔍 Step 1: Validating configuration...');
    validateConfig();
    
    // 🛡️ STEP 2: Compliance validation (auditor-proof)
    logger.info('🛡️ Step 2: Validating compliance requirements...');
    await validateCompliance();
    
    // 🏗️ STEP 3: Initialize Express application
    logger.info('🏗️ Step 3: Initializing Express application...');
    const app = express();
    
    // 🔒 STEP 4: Configure security-first middleware
    logger.info('🔒 Step 4: Configuring security middleware...');
    configureExpress(app);
    
    // 📊 STEP 5: Add audit logging (comprehensive trail)
    logger.info('📊 Step 5: Enabling comprehensive audit logging...');
    app.use(auditLoggerMiddleware);
    
    // 🛣️ STEP 6: Configure routes (minimal attack surface)
    logger.info('🛣️ Step 6: Configuring routes...');
    app.use('/auth', authRoutes);
    app.use('/api', logRoutes);
    
    // 🚨 STEP 7: Error handling (security-first)
    logger.info('🚨 Step 7: Configuring error handling...');
    app.use(errorHandler);
    
    // 🔧 STEP 8: Start retention service (GDPR compliance)
    logger.info('🔧 Step 8: Starting GDPR retention service...');
    startRetentionService();
    
    // 🚀 STEP 9: Start server with validation
    const PORT = validatePort(process.env.BACKEND_PORT);
    const HOST = process.env.BACKEND_HOST || '0.0.0.0';
    
    logger.info('🚀 Step 9: Starting HTTP server...');
    const server = app.listen(PORT, HOST, () => {
      logger.info(`✅ CORE-BACKEND Nuclear Service Online`, {
        port: PORT,
        host: HOST,
        environment: process.env.NODE_ENV || 'development',
        pid: process.pid,
        startup_time: new Date().toISOString(),
        classification: 'CONFIDENTIAL',
        compliance_status: 'ACTIVE'
      });
      
      // Log successful startup for audit trail
      nuclearAuditLogger.logEvent(
        'SERVICE_STARTED' as any,
        'Nuclear service startup completed successfully',
        'SUCCESS',
        {
          resource_type: 'core_backend_service',
          resource_id: 'core-backend',
          metadata: {
            service: 'core-backend',
            version: require('../package.json').version,
            pid: process.pid,
            compliance_validated: true,
            security_enabled: true,
            startup_time: new Date().toISOString()
          }
        }
      );
    });
    
    // 🛑 STEP 10: Configure graceful shutdown
    logger.info('🛑 Step 10: Configuring graceful shutdown...');
    configureGracefulShutdown(server);
    
    return server;
    
  } catch (error) {
    logger.error('💥 CRITICAL: Nuclear service startup failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
      classification: 'CRITICAL',
      incident_type: 'STARTUP_FAILURE'
    });
    
    // Log critical failure for audit
    nuclearAuditLogger.logEvent(
      'SERVICE_STARTUP_FAILED' as any,
      'Nuclear service startup failed',
      'FAILURE',
      {
        resource_type: 'core_backend_service',
        resource_id: 'core-backend',
        metadata: {
          error: error instanceof Error ? error.message : String(error),
          timestamp: new Date().toISOString(),
          compliance_impact: 'SERVICE_UNAVAILABLE'
        }
      }
    );
    
    process.exit(1);
  }
}

/**
 * Validate and normalize port number
 * Ensures port is valid for security and compliance
 */
function validatePort(port: string | undefined): number {
  if (!port) {
    throw new Error('BACKEND_PORT environment variable is required');
  }
  
  const portNumber = parseInt(port, 10);
  
  if (isNaN(portNumber) || portNumber <= 0 || portNumber > 65535) {
    throw new Error(`Invalid port number: ${port}`);
  }
  
  if (portNumber < 1024 && process.getuid && process.getuid() !== 0) {
    throw new Error(`Port ${portNumber} requires root privileges`);
  }
  
  return portNumber;
}

/**
 * Configure graceful shutdown handlers
 * Ensures clean shutdown with audit trail
 */
function configureGracefulShutdown(server: Server): void {
  const shutdown = gracefulShutdown(server, {
    timeout: 30000, // 30 seconds timeout
    onShutdown: async () => {
      logger.info('🔄 Graceful shutdown initiated...');
      
      // Log shutdown for audit trail
      nuclearAuditLogger.logEvent(
        'SERVICE_SHUTDOWN' as any,
        'Graceful service shutdown initiated',
        'SUCCESS',
        {
          resource_type: 'core_backend_service',
          resource_id: 'core-backend',
          metadata: {
            service: 'core-backend',
            pid: process.pid,
            shutdown_time: new Date().toISOString(),
            reason: 'GRACEFUL_SHUTDOWN'
          }
        }
      );
    }
  });
  
  // Handle different shutdown signals
  process.on('SIGTERM', () => {
    logger.info('📡 SIGTERM received, starting graceful shutdown...');
    shutdown('SIGTERM');
  });
  
  process.on('SIGINT', () => {
    logger.info('📡 SIGINT received, starting graceful shutdown...');
    shutdown('SIGINT');
  });
  
  process.on('SIGUSR2', () => {
    logger.info('📡 SIGUSR2 received (nodemon restart), starting graceful shutdown...');
    shutdown('SIGUSR2');
  });
  
  // Handle uncaught exceptions and rejections
  process.on('uncaughtException', (error) => {
    logger.error('💥 CRITICAL: Uncaught exception', {
      error: error.message,
      stack: error.stack,
      classification: 'CRITICAL',
      incident_type: 'UNCAUGHT_EXCEPTION'
    });
    
    nuclearAuditLogger.logEvent(
      'UNCAUGHT_EXCEPTION' as any,
      'Critical uncaught exception occurred',
      'FAILURE',
      {
        resource_type: 'core_backend_service',
        resource_id: 'core-backend',
        metadata: {
          error: error.message,
          stack: error.stack,
          pid: process.pid,
          compliance_impact: 'CRITICAL'
        }
      }
    );
    
    shutdown('UNCAUGHT_EXCEPTION');
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('💥 CRITICAL: Unhandled promise rejection', {
      reason: String(reason),
      promise: String(promise),
      classification: 'CRITICAL',
      incident_type: 'UNHANDLED_REJECTION'
    });
    
    nuclearAuditLogger.logEvent(
      'UNHANDLED_REJECTION' as any,
      'Critical unhandled promise rejection occurred',
      'FAILURE',
      {
        resource_type: 'core_backend_service',
        resource_id: 'core-backend',
        metadata: {
          reason: String(reason),
          pid: process.pid,
          compliance_impact: 'CRITICAL'
        }
      }
    );
    
    shutdown('UNHANDLED_REJECTION');
  });
}

// 🚀 Start the nuclear service
if (require.main === module) {
  startNuclearService().catch((error) => {
    console.error('💥 Failed to start nuclear service:', error);
    process.exit(1);
  });
}

export default startNuclearService;