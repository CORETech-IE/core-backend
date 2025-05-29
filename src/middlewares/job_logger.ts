// utils/job_logger.ts
import { createLogger, format, transports } from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import path from 'path';
import fs from 'fs';

const logDir = path.join(__dirname, '..', '..', 'logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir);

// 📦 Config of the log files
const logRotationConfig = {
  filename: 'report_jobs-%DATE%.log',
  maxSize: '10m',
  maxFiles: '15d',
  zippedArchive: true,
  datePattern: 'YYYY-MM-DD', // required
};

const job_logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.printf(({ timestamp, level, message, ...meta }) => {
      const base = `[${timestamp}] ${level.toUpperCase()} - `;
    
      if (typeof message === "string") {
        return base + message;
      } else {
        // Si es objeto (estructurado), lo convertimos bonito
        return base + JSON.stringify({ message, ...meta });
      }
    })    
  ),
  transports: [
    new DailyRotateFile({
      filename: path.join(logDir, logRotationConfig.filename),
      datePattern: logRotationConfig.datePattern,
      maxSize: logRotationConfig.maxSize,
      maxFiles: logRotationConfig.maxFiles,
      zippedArchive: logRotationConfig.zippedArchive,
    }),
    new transports.Console(),
  ],
});

export default job_logger;
