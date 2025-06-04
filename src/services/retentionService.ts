/**
 * 🚨 CORE-BACKEND: Nuclear Data Retention Service
 * 
 * Automated GDPR-compliant data retention and deletion
 * Implements Article 17 (Right to Erasure) with comprehensive audit trail
 * 
 * Classification: CONFIDENTIAL (data processing service)
 * Retention: 10 years (regulatory requirement)
 * Review Date: Every 3 months (critical compliance component)
 */

import cron from 'node-cron';
import db from '../config/db';
import logger from '../utils/logger';
import nuclearAuditLogger from '../middlewares/auditLogger';

/**
 * Retention policy interface
 */
interface RetentionPolicy {
  table_name: string;
  retention_column: string;
  classification_column?: string;
  description: string;
  default_retention_days: number;
  classification_overrides?: Record<string, number>;
}

/**
 * Deletion result interface
 */
interface DeletionResult {
  table_name: string;
  records_deleted: number;
  oldest_record_deleted?: string;
  newest_record_deleted?: string;
  deletion_duration_ms: number;
  errors: string[];
}

/**
 * Retention service statistics
 */
interface RetentionStats {
  total_tables_processed: number;
  total_records_deleted: number;
  total_duration_ms: number;
  successful_deletions: number;
  failed_deletions: number;
  tables_with_errors: string[];
}

/**
 * Nuclear retention policies
 * Defines retention rules for all data tables
 */
const RETENTION_POLICIES: RetentionPolicy[] = [
  {
    table_name: 'logs',
    retention_column: 'retention_until',
    classification_column: 'classification',
    description: 'Application logs with classification-based retention',
    default_retention_days: 365, // 1 year default
    classification_overrides: {
      'public': 30,        // 30 days
      'internal': 365,     // 1 year  
      'confidential': 2555, // 7 years
      'restricted': 3650   // 10 years
    }
  },
  {
    table_name: 'audit_logs',
    retention_column: 'retention_until',
    description: 'Audit logs with regulatory retention requirements',
    default_retention_days: 2555 // 7 years for audit trails
  },
  {
    table_name: 'error_logs',
    retention_column: 'retention_until',
    description: 'Error logs for troubleshooting and security analysis',
    default_retention_days: 1095 // 3 years
  },
  {
    table_name: 'security_events',
    retention_column: 'retention_until',
    description: 'Security events for incident investigation',
    default_retention_days: 3650 // 10 years for security events
  }
];

/**
 * Service state tracking
 */
interface ServiceState {
  isRunning: boolean;
  lastRunTime: Date | null;
  nextRunTime: Date | null;
  totalRunsCompleted: number;
  totalRecordsDeleted: number;
  cronJob: cron.ScheduledTask | null;
}

let serviceState: ServiceState = {
  isRunning: false,
  lastRunTime: null,
  nextRunTime: null,
  totalRunsCompleted: 0,
  totalRecordsDeleted: 0,
  cronJob: null
};

/**
 * Validate retention policy configuration
 */
function validateRetentionPolicies(): void {
  logger.info('🔍 Validating retention policies...', {
    classification: 'INTERNAL',
    audit_event: 'RETENTION_POLICY_VALIDATION_STARTED',
    policy_count: RETENTION_POLICIES.length
  });
  
  const errors: string[] = [];
  
  RETENTION_POLICIES.forEach((policy, index) => {
    // Check required fields
    if (!policy.table_name) {
      errors.push(`Policy ${index}: Missing table_name`);
    }
    
    if (!policy.retention_column) {
      errors.push(`Policy ${index}: Missing retention_column`);
    }
    
    if (!policy.description) {
      errors.push(`Policy ${index}: Missing description`);
    }
    
    if (!policy.default_retention_days || policy.default_retention_days <= 0) {
      errors.push(`Policy ${index}: Invalid default_retention_days`);
    }
    
    // Validate classification overrides
    if (policy.classification_overrides) {
      Object.entries(policy.classification_overrides).forEach(([classification, days]) => {
        if (days <= 0) {
          errors.push(`Policy ${index}: Invalid retention days for classification ${classification}`);
        }
      });
    }
  });
  
  if (errors.length > 0) {
    logger.error('💥 Retention policy validation failed', {
      classification: 'CRITICAL',
      audit_event: 'RETENTION_POLICY_VALIDATION_FAILED',
      errors
    });
    
    throw new Error(`Retention policy validation failed: ${errors.join(', ')}`);
  }
  
  logger.info('✅ Retention policies validated successfully', {
    classification: 'INTERNAL',
    audit_event: 'RETENTION_POLICY_VALIDATION_SUCCESS',
    validated_policies: RETENTION_POLICIES.length
  });
}

/**
 * Check if table exists in database
 */
async function tableExists(tableName: string): Promise<boolean> {
  try {
    const result = await db.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = $1
      )
    `, [tableName]);
    
    return result.rows[0].exists;
  } catch (error) {
    logger.warn(`⚠️ Error checking table existence: ${tableName}`, {
      classification: 'HIGH',
      audit_event: 'TABLE_EXISTENCE_CHECK_ERROR',
      table_name: tableName,
      error: error instanceof Error ? error.message : String(error)
    });
    
    return false;
  }
}

/**
 * Delete expired records from a table
 */
async function deleteExpiredRecords(policy: RetentionPolicy): Promise<DeletionResult> {
  const startTime = Date.now();
  const result: DeletionResult = {
    table_name: policy.table_name,
    records_deleted: 0,
    deletion_duration_ms: 0,
    errors: []
  };
  
  try {
    logger.info(`🧹 Starting deletion for table: ${policy.table_name}`, {
      classification: 'HIGH',
      audit_event: 'RETENTION_DELETION_STARTED',
      table_name: policy.table_name,
      policy_description: policy.description
    });
    
    // Check if table exists
    const exists = await tableExists(policy.table_name);
    if (!exists) {
      const error = `Table ${policy.table_name} does not exist`;
      result.errors.push(error);
      
      logger.warn(`⚠️ Table not found: ${policy.table_name}`, {
        classification: 'HIGH',
        audit_event: 'RETENTION_TABLE_NOT_FOUND',
        table_name: policy.table_name
      });
      
      return result;
    }
    
    // Build deletion query
    const deleteQuery = `
      DELETE FROM ${policy.table_name}
      WHERE ${policy.retention_column} <= NOW()
      RETURNING 
        COUNT(*) as deleted_count,
        MIN(created_at) as oldest_deleted,
        MAX(created_at) as newest_deleted
    `;
    
    // Execute deletion within transaction
    await db.withTransaction(async (client) => {
      // First, get count of records to be deleted for audit
      const countQuery = `
        SELECT COUNT(*) as expired_count
        FROM ${policy.table_name}
        WHERE ${policy.retention_column} <= NOW()
      `;
      
      const countResult = await client.query(countQuery);
      const expiredCount = parseInt(countResult.rows[0].expired_count);
      
      if (expiredCount === 0) {
        logger.info(`ℹ️ No expired records found in ${policy.table_name}`, {
          classification: 'INTERNAL',
          audit_event: 'RETENTION_NO_EXPIRED_RECORDS',
          table_name: policy.table_name
        });
        return;
      }
      
      // Log before deletion for audit trail
      logger.info(`🗑️ Deleting ${expiredCount} expired records from ${policy.table_name}`, {
        classification: 'HIGH',
        audit_event: 'RETENTION_DELETION_EXECUTING',
        table_name: policy.table_name,
        records_to_delete: expiredCount
      });
      
      // Execute deletion
      const deleteResult = await client.query(`
        DELETE FROM ${policy.table_name}
        WHERE ${policy.retention_column} <= NOW()
      `);
      
      result.records_deleted = deleteResult.rowCount || 0;
      
      // Log successful deletion
      nuclearAuditLogger.logEvent(
        'DATA_RETENTION_CLEANUP' as any,
        `Automated retention cleanup for ${policy.table_name}`,
        'SUCCESS',
        {
          resource_type: 'database_table',
          resource_id: policy.table_name,
          metadata: {
            table_name: policy.table_name,
            records_deleted: result.records_deleted,
            policy_description: policy.description,
            legal_basis: 'gdpr_article_17',
            data_categories: ['log_data', 'application_data']
          }
        }
      );
      
    });
    
    result.deletion_duration_ms = Date.now() - startTime;
    
    logger.info(`✅ Deletion completed for ${policy.table_name}`, {
      classification: 'HIGH',
      audit_event: 'RETENTION_DELETION_COMPLETED',
      table_name: policy.table_name,
      records_deleted: result.records_deleted,
      duration_ms: result.deletion_duration_ms
    });
    
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    result.errors.push(errorMessage);
    result.deletion_duration_ms = Date.now() - startTime;
    
    logger.error(`💥 Deletion failed for ${policy.table_name}`, {
      classification: 'CRITICAL',
      audit_event: 'RETENTION_DELETION_FAILED',
      table_name: policy.table_name,
      error: errorMessage,
      duration_ms: result.deletion_duration_ms
    });
    
    // Log failed deletion for audit
    nuclearAuditLogger.logEvent(
      'DATA_RETENTION_CLEANUP' as any,
      `Failed retention cleanup for ${policy.table_name}`,
      'FAILURE',
      {
        resource_type: 'database_table',
        resource_id: policy.table_name,
        metadata: {
          table_name: policy.table_name,
          error_message: errorMessage,
          policy_description: policy.description
        }
      }
    );
  }
  
  return result;
}

/**
 * Execute retention cleanup for all policies
 */
async function executeRetentionCleanup(): Promise<RetentionStats> {
  const startTime = Date.now();
  
  logger.info('🚀 Starting scheduled retention cleanup', {
    classification: 'HIGH',
    audit_event: 'RETENTION_CLEANUP_STARTED',
    policies_to_process: RETENTION_POLICIES.length,
    scheduled_time: new Date().toISOString()
  });
  
  const stats: RetentionStats = {
    total_tables_processed: 0,
    total_records_deleted: 0,
    total_duration_ms: 0,
    successful_deletions: 0,
    failed_deletions: 0,
    tables_with_errors: []
  };
  
  // Process each retention policy
  for (const policy of RETENTION_POLICIES) {
    stats.total_tables_processed++;
    
    try {
      const result = await deleteExpiredRecords(policy);
      
      stats.total_records_deleted += result.records_deleted;
      
      if (result.errors.length > 0) {
        stats.failed_deletions++;
        stats.tables_with_errors.push(policy.table_name);
      } else {
        stats.successful_deletions++;
      }
      
    } catch (error) {
      stats.failed_deletions++;
      stats.tables_with_errors.push(policy.table_name);
      
      logger.error(`💥 Policy execution failed for ${policy.table_name}`, {
        classification: 'CRITICAL',
        audit_event: 'RETENTION_POLICY_EXECUTION_FAILED',
        table_name: policy.table_name,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
  
  stats.total_duration_ms = Date.now() - startTime;
  
  // Update service state
  serviceState.lastRunTime = new Date();
  serviceState.totalRunsCompleted++;
  serviceState.totalRecordsDeleted += stats.total_records_deleted;
  
  // Log completion statistics
  logger.info('📊 Retention cleanup completed', {
    classification: 'HIGH',
    audit_event: 'RETENTION_CLEANUP_COMPLETED',
    ...stats,
    next_run_time: serviceState.nextRunTime?.toISOString()
  });
  
  // Log compliance event
  nuclearAuditLogger.logEvent(
    'DATA_RETENTION_CLEANUP' as any,
    'Scheduled data retention cleanup completed',
    stats.failed_deletions > 0 ? 'PARTIAL' : 'SUCCESS',
    {
      metadata: {
        total_records_deleted: stats.total_records_deleted,
        tables_processed: stats.total_tables_processed,
        successful_deletions: stats.successful_deletions,
        failed_deletions: stats.failed_deletions,
        duration_ms: stats.total_duration_ms,
        compliance_framework: 'GDPR_Article_17',
        legal_basis: 'automated_retention_policy'
      }
    }
  );
  
  return stats;
}

/**
 * Calculate next run time
 */
function calculateNextRunTime(cronExpression: string): Date | null {
  try {
    // Use cron.validate to check if expression is valid
    const isValid = cron.validate(cronExpression);
    if (!isValid) {
      throw new Error('Invalid cron expression');
    }
    
    // For next run time, we'll calculate it manually or return null
    // node-cron doesn't expose nextDates method reliably
    logger.info(`ℹ️ Next run scheduled with cron: ${cronExpression}`, {
      classification: 'INTERNAL',
      audit_event: 'RETENTION_SCHEDULE_CALCULATED',
      cron_expression: cronExpression
    });
    
    return null; // Will be updated when job actually runs
  } catch (error) {
    logger.error('💥 Error validating cron expression', {
      classification: 'HIGH',
      audit_event: 'RETENTION_SCHEDULE_CALCULATION_ERROR',
      cron_expression: cronExpression,
      error: error instanceof Error ? error.message : String(error)
    });
    return null;
  }
}

/**
 * Start the retention service
 */
export function startRetentionService(cronExpression: string = '0 2 * * *'): void {
  try {
    // Validate retention policies first
    validateRetentionPolicies();
    
    // Check if already running
    if (serviceState.isRunning) {
      logger.warn('⚠️ Retention service already running', {
        classification: 'INTERNAL',
        audit_event: 'RETENTION_SERVICE_ALREADY_RUNNING'
      });
      return;
    }
    
    // Calculate next run time (simplified)
    serviceState.nextRunTime = calculateNextRunTime(cronExpression);
    
    // Create and start cron job
    serviceState.cronJob = cron.schedule(cronExpression, async () => {
      try {
        // Update next run time when job executes
        serviceState.nextRunTime = new Date(Date.now() + 24 * 60 * 60 * 1000); // Approximate next day for daily jobs
        await executeRetentionCleanup();
      } catch (error) {
        logger.error('💥 CRITICAL: Retention cleanup execution failed', {
          classification: 'CRITICAL',
          audit_event: 'RETENTION_CLEANUP_EXECUTION_ERROR',
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }, {
      scheduled: true,
      timezone: 'UTC' // Always use UTC for consistency
    });
    
    serviceState.isRunning = true;
    
    logger.info('🚀 Nuclear retention service started successfully', {
      classification: 'HIGH',
      audit_event: 'RETENTION_SERVICE_STARTED',
      cron_expression: cronExpression,
      next_run_time: serviceState.nextRunTime?.toISOString(),
      policies_configured: RETENTION_POLICIES.length,
      timezone: 'UTC'
    });
    
    // Log compliance initialization
    nuclearAuditLogger.logEvent(
      'SERVICE_STARTED' as any,
      'GDPR retention service initialized',
      'SUCCESS',
      {
        resource_type: 'retention_service',
        resource_id: 'data_retention_service',
        metadata: {
          service_name: 'data_retention_service',
          compliance_framework: 'GDPR_Article_17',
          retention_policies: RETENTION_POLICIES.length,
          schedule: cronExpression
        }
      }
    );
    
  } catch (error) {
    logger.error('💥 CRITICAL: Failed to start retention service', {
      classification: 'CRITICAL',
      audit_event: 'RETENTION_SERVICE_START_FAILED',
      error: error instanceof Error ? error.message : String(error)
    });
    
    throw error;
  }
}

/**
 * Stop the retention service
 */
export function stopRetentionService(): void {
  if (!serviceState.isRunning || !serviceState.cronJob) {
    logger.warn('⚠️ Retention service not running', {
      classification: 'INTERNAL',
      audit_event: 'RETENTION_SERVICE_NOT_RUNNING'
    });
    return;
  }
  
  serviceState.cronJob.stop();
  // Note: node-cron ScheduledTask doesn't have destroy() method
  serviceState.cronJob = null;
  serviceState.isRunning = false;
  serviceState.nextRunTime = null;
  
  logger.info('🛑 Retention service stopped', {
    classification: 'HIGH',
    audit_event: 'RETENTION_SERVICE_STOPPED',
    total_runs_completed: serviceState.totalRunsCompleted,
    total_records_deleted: serviceState.totalRecordsDeleted
  });
}

/**
 * Get service status
 */
export function getRetentionServiceStatus(): {
  isRunning: boolean;
  lastRunTime: Date | null;
  nextRunTime: Date | null;
  totalRunsCompleted: number;
  totalRecordsDeleted: number;
  policies: RetentionPolicy[];
} {
  return {
    isRunning: serviceState.isRunning,
    lastRunTime: serviceState.lastRunTime,
    nextRunTime: serviceState.nextRunTime,
    totalRunsCompleted: serviceState.totalRunsCompleted,
    totalRecordsDeleted: serviceState.totalRecordsDeleted,
    policies: [...RETENTION_POLICIES]
  };
}

/**
 * Manual retention cleanup (for testing or emergency)
 */
export async function manualRetentionCleanup(): Promise<RetentionStats> {
  logger.info('🔧 Manual retention cleanup initiated', {
    classification: 'HIGH',
    audit_event: 'MANUAL_RETENTION_CLEANUP_STARTED'
  });
  
  const stats = await executeRetentionCleanup();
  
  logger.info('✅ Manual retention cleanup completed', {
    classification: 'HIGH',
    audit_event: 'MANUAL_RETENTION_CLEANUP_COMPLETED',
    ...stats
  });
  
  return stats;
}

export default {
  startRetentionService,
  stopRetentionService,
  getRetentionServiceStatus,
  manualRetentionCleanup
};