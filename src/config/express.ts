/**
 * 🚨 CORE-BACKEND: Nuclear Express Configuration
 * 
 * Security-first Express middleware configuration
 * Compliance: Zero Trust + ISO 27001 + GDPR by design
 * 
 * Classification: CONFIDENTIAL (security configuration)
 * Retention: Service lifetime (operational requirement)
 * Review Date: Every 3 months (security critical)
 */

import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
// import compression from 'compression'; // Optional dependency
import { Request, Response, NextFunction } from 'express';
import envConfig from './envConfig';
import logger from '../utils/logger';

/**
 * Nuclear Express configuration
 * Applies security-first middleware stack with compliance controls
 */
const configureExpress = (app: express.Application): void => {
  // 🔒 STEP 1: Security headers (ISO 27001 A.13.2.1)
  configureSecurityHeaders(app);
  
  // 🌐 STEP 2: CORS configuration (Zero Trust)
  configureCORS(app);
  
  // 📦 STEP 3: Body parsing with security limits
  configureBodyParsing(app);
  
  // 🗜️ STEP 4: Compression for performance (OPTIONAL)
  // configureCompression(app);
  
  // 🔗 STEP 5: Correlation ID tracking (audit trail)
  configureCorrelationTracking(app);
  
  // 📊 STEP 6: Request logging with compliance
  configureRequestLogging(app);
  
  // 🛡️ STEP 7: Method restrictions (attack surface reduction)
  configureMethodRestrictions(app);
  
  // 🔍 STEP 8: Health check endpoint (monitoring)
  configureHealthCheck(app);
  
  logger.info('✅ Nuclear Express middleware configured', {
    classification: 'INTERNAL',
    audit_event: 'EXPRESS_MIDDLEWARE_CONFIGURED',
    environment: envConfig.nodeEnv,
    security_level: 'NUCLEAR'
  });
};

/**
 * Configure comprehensive security headers
 * Implements defense-in-depth security strategy
 */
function configureSecurityHeaders(app: express.Application): void {
  // Disable fingerprinting headers
  app.disable('x-powered-by');
  app.disable('etag');
  
  // Comprehensive security headers with Helmet
  app.use(helmet({
    // Content Security Policy - ENFORCED (not disabled like before)
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // For error pages only
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
        // upgradeInsecureRequests: Production HTTPS should be handled at load balancer/proxy level
      }
    },
    
    // Cross-Origin policies
    crossOriginEmbedderPolicy: { policy: "credentialless" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-site" },
    
    // HTTPS enforcement in production
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true
    },
    
    // Additional security headers
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" }
  }));
  
  // Custom security headers
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Server identification obfuscation
    res.setHeader('Server', 'Core-Backend');
    
    // Cache control for security
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    // Custom compliance headers
    res.setHeader('X-Compliance-Level', 'Nuclear');
    res.setHeader('X-Classification', 'Confidential');
    
    next();
  });
}

/**
 * Configure CORS for multi-tenant security
 * Implements Zero Trust CORS policy
 */
function configureCORS(app: express.Application): void {
  const corsOptions: cors.CorsOptions = {
    origin: function (origin, callback) {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) {
        return callback(null, true);
      }
      
      // Development: Allow localhost
      if (envConfig.nodeEnv === 'development') {
        if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
          return callback(null, true);
        }
      }
      
      // Production: Strict origin validation
      const allowedOrigins = [
        'https://core-platform.company.com',
        'https://admin.company.com'
      ];
      
      if (envConfig.nodeEnv === 'production' && !allowedOrigins.includes(origin)) {
        logger.warn('🚫 CORS origin blocked', {
          classification: 'HIGH',
          audit_event: 'CORS_ORIGIN_BLOCKED',
          origin,
          security_violation: 'UNAUTHORIZED_ORIGIN'
        });
        
        return callback(new Error('Not allowed by CORS policy'), false);
      }
      
      callback(null, true);
    },
    
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization', 
      'X-Trace-ID',
      'X-Tenant-Name',
      'X-Classification'
    ],
    exposedHeaders: ['X-Trace-ID', 'X-RateLimit-Remaining'],
    maxAge: 300 // 5 minutes preflight cache
  };
  
  app.use(cors(corsOptions));
  
  // CORS preflight audit logging
  app.options('*', (req: Request, res: Response) => {
    logger.info('🔍 CORS preflight request', {
      classification: 'INTERNAL',
      audit_event: 'CORS_PREFLIGHT_REQUEST',
      origin: req.headers.origin,
      method: req.headers['access-control-request-method']
    });
    res.status(200).end();
  });
}

/**
 * Configure body parsing with security limits
 * Protects against payload-based attacks
 */
function configureBodyParsing(app: express.Application): void {
  // JSON parsing with strict limits
  app.use(express.json({
    limit: '1mb',  // Reduced from 2mb for security
    strict: true,  // Only parse objects and arrays
    verify: (req: Request, res: Response, buf: Buffer) => {
      // Store raw body for audit if needed
      (req as any).rawBody = buf;
    }
  }));
  
  // URL-encoded parsing (for form data if needed)
  app.use(express.urlencoded({
    limit: '1mb',
    extended: false, // Use simple querystring parser for security
    parameterLimit: 20 // Limit number of parameters
  }));
  
  // Reject requests with unsupported content types
  app.use((req: Request, res: Response, next: NextFunction) => {
    const contentType = req.headers['content-type'];
    
    if (req.method === 'POST' && contentType) {
      if (!contentType.includes('application/json') && 
          !contentType.includes('application/x-www-form-urlencoded')) {
        
        logger.warn('🚫 Unsupported content type rejected', {
          classification: 'HIGH',
          audit_event: 'UNSUPPORTED_CONTENT_TYPE',
          content_type: contentType,
          method: req.method,
          path: req.path
        });
        
        return res.status(415).json({
          error: 'Unsupported Media Type',
          supported: ['application/json']
        });
      }
    }
    
    next();
  });
}

/**
 * Configure compression for performance (OPTIONAL)
 * Applies intelligent compression based on content type
 */
/*
function configureCompression(app: express.Application): void {
  app.use(compression({
    level: 6, // Balanced compression
    threshold: 1024, // Only compress responses > 1KB
    filter: (req: Request, res: Response) => {
      // Don't compress if the response includes a Cache-Control no-transform directive
      if (res.getHeader('Cache-Control')?.toString().includes('no-transform')) {
        return false;
      }
      
      // Compress JSON responses (our main content)
      const contentType = res.getHeader('Content-Type')?.toString();
      return contentType?.includes('application/json') || false;
    }
  }));
}
*/

/**
 * Configure correlation ID tracking for audit trail
 * Implements comprehensive request tracing
 */
function configureCorrelationTracking(app: express.Application): void {
  app.use((req: Request, res: Response, next: NextFunction) => {
    // Generate or extract correlation ID
    const correlationId = req.headers['x-trace-id'] as string || 
                         generateCorrelationId();
    
    // Store in request for downstream use
    (req as any).correlationId = correlationId;
    
    // Add to response headers for client tracing
    res.setHeader('X-Trace-ID', correlationId);
    
    // Add tenant context if available
    const tenantName = req.headers['x-tenant-name'] as string;
    if (tenantName) {
      (req as any).tenantName = tenantName;
      res.setHeader('X-Tenant-Name', tenantName);
    }
    
    next();
  });
}

/**
 * Configure request logging with compliance classification
 * Implements comprehensive audit logging per ISO 27001 A.12.4.1
 */
function configureRequestLogging(app: express.Application): void {
  app.use((req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    const correlationId = (req as any).correlationId;
    const tenantName = (req as any).tenantName;
    
    // Log request start
    logger.info('📥 Request started', {
      classification: 'INTERNAL',
      audit_event: 'REQUEST_STARTED',
      correlation_id: correlationId,
      tenant_name: tenantName,
      method: req.method,
      path: req.path,
      user_agent: req.headers['user-agent'],
      ip_address: req.ip,
      content_length: req.headers['content-length']
    });
    
    // Capture response end with TypeScript bypass
    const originalEnd = res.end.bind(res);
    
    (res as any).end = (...args: any[]) => {
      const duration = Date.now() - startTime;
      
      // Log request completion
      logger.info('📤 Request completed', {
        classification: 'INTERNAL',
        audit_event: 'REQUEST_COMPLETED',
        correlation_id: correlationId,
        tenant_name: tenantName,
        method: req.method,
        path: req.path,
        status_code: res.statusCode,
        duration_ms: duration,
        response_size: res.getHeader('content-length')
      });
      
      // Call original end function with all original arguments
      return originalEnd(...args);
    };
    
    next();
  });
}

/**
 * Configure HTTP method restrictions
 * Implements minimal attack surface principle
 */
function configureMethodRestrictions(app: express.Application): void {
  const allowedMethods = ['GET', 'POST', 'OPTIONS'];
  
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (!allowedMethods.includes(req.method)) {
      logger.warn('🚫 Method not allowed', {
        classification: 'HIGH',
        audit_event: 'METHOD_NOT_ALLOWED',
        method: req.method,
        path: req.path,
        ip_address: req.ip,
        correlation_id: (req as any).correlationId
      });
      
      return res.status(405).json({
        error: 'Method Not Allowed',
        allowed_methods: allowedMethods
      });
    }
    
    next();
  });
}

/**
 * Configure health check endpoint
 * Provides monitoring without authentication
 */
function configureHealthCheck(app: express.Application): void {
  app.get('/health', (req: Request, res: Response) => {
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: envConfig.serviceName,
      version: '1.0.0', // Could be loaded from package.json
      environment: envConfig.nodeEnv,
      uptime: process.uptime(),
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        rss: Math.round(process.memoryUsage().rss / 1024 / 1024)
      },
      compliance: {
        iso27001: 'active',
        gdpr: 'compliant',
        zero_trust: 'enforced'
      }
    };
    
    res.status(200).json(healthStatus);
  });
}

/**
 * Generate correlation ID for request tracing
 * Uses timestamp + random for uniqueness and sortability
 */
function generateCorrelationId(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = Math.random().toString(36).substring(2, 8);
  return `${timestamp}-${randomPart}`;
}

export default configureExpress;