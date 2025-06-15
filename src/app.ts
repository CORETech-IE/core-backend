// src/app.ts
import express from 'express';
import { Server } from 'http';
import configureExpress from './config/express';
import authRoutes from './routes/authRoutes';
import logRoutes from './routes/logRoutes';
import { errorHandler } from './middlewares/errorHandler';
import logger from './utils/logger';
import { getConfig } from './config/envConfig';
import heartbeatRoutes from './routes/heartbeatRoutes';

async function startService(): Promise<void> {
  try {
    // Cargar configuración
    logger.info('🔄 Loading configuration...');
    const config = await getConfig();
    
    // Crear app Express
    const app = express();
    
    // Configurar middleware
    configureExpress(app);
    
    // Rutas: from more specific to less specifiv
    app.use('/api/heartbeat', heartbeatRoutes);
    app.use('/auth', authRoutes);
    app.use('/api', logRoutes);
    
    
    // Error handler
    app.use(errorHandler);
    
    // Arrancar servidor
    const PORT = config.backendPort;
    const HOST = config.backendHost;
    
    app.listen(PORT, HOST, () => {
      logger.info(`✅ CORE-BACKEND Service Online`, {
        port: PORT,
        host: HOST,
        environment: config.nodeEnv,
        service: config.serviceName
      });
    });
    
  } catch (error) {
    logger.error('💥 Service startup failed', {
      error: error instanceof Error ? error.message : String(error)
    });
    process.exit(1);
  }
}

// Arrancar
startService();