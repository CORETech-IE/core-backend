import express from "express";
import bodyParser from "body-parser";
import { errorHandler } from "../middlewares/errorHandler";
import logger from "../utils/logger";
import { rateLimiter } from "../middlewares/rateLimiter";
import helmet from "helmet"; // Security middleware to set various HTTP headers
import { Request, Response, NextFunction } from "express";

const configureExpress = (app: express.Application) => {
  // Disable the 'X-Powered-By' header to prevent information leakage
  // This header can reveal the technology stack used by the server
  // and can be exploited by attackers.
  app.disable("x-powered-by");

  // Security Middleware: Set various HTTP headers for security
  // This helps protect your app from some well-known web vulnerabilities
  // by setting HTTP headers appropriately.
  // For example, it can help prevent XSS attacks, clickjacking, etc.
  app.use(
    helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: false,
    })
  );

  // Middleware Configurations
  // Body parsers with payload size limit (protects against abuse and denial of service)
  app.use(bodyParser.json({ limit: "2mb" }));
  app.use(bodyParser.urlencoded({ extended: true, limit: "2mb" }));

  // Rate Limiter Middleware: Limit the number of requests
  // to prevent abuse and DDoS attacks
  app.use(rateLimiter);

  // Logging Middleware: Log every request
  app.use((req, res, next) => {
    logger.info(`Received ${req.method} request for ${req.url}`);
    next();
  });

  // Custom Middleware: Check if the request method is allowed
  // This middleware checks if the request method is one of the allowed methods
  // (GET, POST in this case). If not, it sends a 405 Method Not Allowed response.
  const allowedMethods = ["GET", "POST"];
  app.use((req, res, next) => {
    if (!allowedMethods.includes(req.method)) {
      return res.status(405).send({ error: "Method Not Allowed" });
    }
    next();
  });

  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error("🛑 Middleware DEBUG error caught:", err);
    next(err); // Pásalo al errorHandler real
  });

  // Here, you can add other configurations, for example:
  // CORS headers, other middlewares, session configuration, etc.

  // Error Handling Middleware - should be added as one of the last middlewares
  app.use(errorHandler);
};

export default configureExpress;
