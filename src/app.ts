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

validateConfig();
startHeartbeat();

const app = express();


const fakeReq = {} as Request;
logWithTrace(fakeReq, {
  job_type: 'BOOT',
  action: 'CONFIG_PATHS',
  level: 'info',
  emit: false,
  data: {
    config_paths: {
      reports: process.env.REPORTS_CONFIG_PATH || 'default-reports-path',
      logs: process.env.LOGS_CONFIG_PATH || 'default-logs-path',
      metrics: process.env.METRICS_CONFIG_PATH || 'default-metrics-path',
    }
  }
}).catch(() => {});

configureExpress(app);
app.use('/auth', authRoutes);
configureRouter(app);

app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`✅ Server is running on http://localhost:${PORT}`);
});

export default app;