import { createLogger, format, transports } from 'winston';

const { combine, timestamp, printf, colorize } = format;

const customFormat = printf(({ level, message, timestamp }) => {
    return `${timestamp} [${level}]: ${message}`;
});

const logger = createLogger({
    format: combine(
        timestamp(),
        customFormat
    ),
    transports: [
        new transports.Console({
            format: combine(colorize(), timestamp(), customFormat),
            level: process.env.LOG_LEVEL || 'info',
        }),
        new transports.File({ 
            filename: 'app.log',
            level: 'info',
            handleExceptions: true,  // If you want to handle unhandled exceptions
        }),
    ],
    exitOnError: false,  // If you don't want the application to exit on unhandled exceptions
});

export default logger;
