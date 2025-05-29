// middlewares/rateLimiter.ts
import rateLimit from 'express-rate-limit';

export const rateLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 100,                   // máx 100 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please try again later.'
});

export const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,  // 1 minute
  max: 10,                   // only 10 login attempts per minute
  message: 'Too many login attempts. Please try again in 1 minutes.'
});
