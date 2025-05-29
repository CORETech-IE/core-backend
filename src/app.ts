import express from 'express';
import { Request } from 'express';
import { startHeartbeat } from './services/heartbeatEmitter';
import { errorHandler } from './middlewares/errorHandler';
import logger from './utils/logger';
import authRoutes from './routes/authRoutes';
import { validateConfig } from './config/config-validator';
import { logWithTrace } from './middlewares/logWithTrace';
//import config from './config/reportsConfig';
import configureExpress from './config/express';
import configureRouter from './routes/appRoutes';

// Validate configuration before starting the server
// This ensures all required environment variables are set
// and the application is ready to run
validateConfig();

// Start the heartbeat service to emit periodic heartbeat signals
// This is useful for monitoring the health of the application
// and ensuring it is running as expected
startHeartbeat();

const app = express();


configureExpress(app);
app.use('/auth', authRoutes);
configureRouter(app);

app.use(errorHandler);

const PORT = process.env.BACKEND_PORT;
app.listen(PORT, () => {
  logger.info(`✅ Server is running on http://localhost:${PORT}`);
});

export default app;