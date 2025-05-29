import dotenv from "dotenv";
dotenv.config();

// src/config/envConfig.ts
// Importing environment variables and setting up configuration for the application
// This file is responsible for loading environment variables and constructing the configuration object

const coreApiHost = process.env.CORE_API_HOST;
const backendPort = process.env.BACKEND_PORT;

const envConfig = {
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  tenantId: process.env.TENANT_CLIENT_ID,
  senderEmail: process.env.SENDER_EMAIL,
  pgHost: process.env.PGHOST,
  pgPort: Number(process.env.PGPORT),
  pgDatabase: process.env.PGDATABASE,
  pgUser: process.env.PGUSER,
  pgPassword: process.env.PGPASSWORD,
  serviceName: process.env.SERVICE_NAME || "",
  tenantClientId: process.env.TENANT_CLIENT_ID,
  jwtSecret: process.env.JWT_SECRET,
  authUsername: process.env.AUTH_USERNAME,
  authPassword: process.env.AUTH_PASSWORD,
  authUrl: `${coreApiHost}:${backendPort}${process.env.AUTH_URL}`, // URL for the authentication service
  apiUrl: `${coreApiHost}:${backendPort}${process.env.BACKEND_URL}`, // Base URL for the API
};

export default envConfig;
