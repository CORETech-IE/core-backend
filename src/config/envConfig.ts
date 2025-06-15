// src/config/envConfig.ts
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import yaml from "js-yaml";

interface EnvironmentConfig {
  // Database
  pgHost: string;
  pgPort: number;
  pgDatabase: string;
  pgUser: string;
  pgPassword: string;
  pgMinConnections: number;
  pgMaxConnections: number;
  pgIdleTimeoutMillis: number;
  pgConnectionTimeoutMillis: number;

  // Auth
  jwtSecret: string;

  // Service
  tenantId: string;
  serviceName: string;
  clientId: string;

  // Network
  backendPort: number;
  backendHost: string;

  // Environment
  nodeEnv: "development" | "test" | "production";
  logLevel: "debug" | "info" | "warn" | "error";
}

let cachedConfig: EnvironmentConfig | null = null;

const loadConfig = (): EnvironmentConfig => {
  if (cachedConfig) return cachedConfig;

  const clientId = process.argv[2] || process.env.CLIENT_ID || "core-dev";
  const gpgPassphrase = process.env.GPG_PASSPHRASE || 
    process.argv.find(arg => arg.startsWith("--gpg-passphrase="))?.split("=")[1];

  if (!gpgPassphrase) {
    throw new Error("GPG passphrase required");
  }

  const envsRepoPath = path.resolve(__dirname, "../../../core-envs-private");
  
  // Load config.yaml
  const yamlPath = path.join(envsRepoPath, `clients/${clientId}/config.yaml`);
  const yamlConfig = yaml.load(fs.readFileSync(yamlPath, "utf8")) as any;
  
  // Decrypt secrets
  const secretsPath = path.join(envsRepoPath, `clients/${clientId}/secrets.sops.yaml`);
  const sopsCmd = process.platform === "win32" 
    ? path.join(envsRepoPath, "tools/win64/sops.exe")
    : "sops";
    
  process.env.GPG_PASSPHRASE = gpgPassphrase;
  const decrypted = execSync(`${sopsCmd} -d --output-type json ${secretsPath}`, {
    encoding: 'utf8'
  });
  const secrets = JSON.parse(decrypted);

  cachedConfig = {
    // Database
    pgHost: yamlConfig.pg_host || "localhost",
    pgPort: parseInt(yamlConfig.pg_port || "5432"),
    pgDatabase: yamlConfig.pg_database || "core_backend_db",
    pgUser: secrets.pg_user || yamlConfig.pg_user,
    pgPassword: secrets.pg_password,
    pgMinConnections: yamlConfig.pg_min_connections || 2,
    pgMaxConnections : yamlConfig.pg_max_connections || 10,
    pgIdleTimeoutMillis : yamlConfig.pg_idle_timeout_millis || 30000,
    pgConnectionTimeoutMillis : yamlConfig.pg_connection_timeout_millis || 2000,

    // Auth
    jwtSecret: secrets.jwt_secret || secrets.internal_jwt_secret,

    // Service
    tenantId: secrets.tenant_id || yamlConfig.tenant_id || clientId,
    serviceName: yamlConfig.service_name || "core-backend",
    clientId: clientId,

    // Network
    backendPort: parseInt(yamlConfig.backend_port || "3000"),
    backendHost: yamlConfig.backend_host || "0.0.0.0",

    // Environment
    nodeEnv: (yamlConfig.node_env || "development") as any,
    logLevel: (yamlConfig.log_level || "info") as any
  };

  return cachedConfig;
};

export const getConfig = async (): Promise<EnvironmentConfig> => {
  return loadConfig();
};

export const getConfigSync = (): EnvironmentConfig => {
  return loadConfig();
};

export default getConfigSync();