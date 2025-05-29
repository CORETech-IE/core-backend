import { Request, Response, NextFunction } from 'express';
import { logWithTrace } from './logWithTrace';
import job_logger from './job_logger';

export const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  const trace_id = (req as any).trace_id || 'n/a';

  // Log to file with Winston
  job_logger.error({
    job_type: 'SYSTEM',
    action: 'UNHANDLED_ERROR',
    trace_id,
    error: {
      message,
      stack: err?.stack || null,
      path: req.originalUrl,
      method: req.method
    }
  });

  // Log to MQTT (async, non-blocking)
  logWithTrace(req, {
    job_type: 'SYSTEM',
    action: 'UNHANDLED_ERROR',
    level: 'error',
    emit: true,
    trace_id,
    data: {
      message,
      stack: err?.stack || null,
      path: req.originalUrl,
      method: req.method
    }
  }).catch(err => {
    console.warn('[errorHandler] logWithTrace failed:', err);
  });

  res.status(statusCode).json({
    status: 'error',
    message,
    trace_id
  });
};
