// src/config/envConfig.ts - CORE-BACKEND VERSION
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import logger from "../utils/logger";

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

  // Auth - OJO: viene de core-services!
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
    throw new Error("GPG passphrase required. Set GPG_PASSPHRASE or use --gpg-passphrase=xxx");
  }

  const envsRepoPath = path.resolve(__dirname, "../../../core-envs-private");
  
  try {
    // 1. Load config.yaml con NUEVA ESTRUCTURA
    const yamlPath = path.join(envsRepoPath, `clients/${clientId}/config.yaml`);
    const yamlContent = fs.readFileSync(yamlPath, "utf8");
    const yamlConfig = yaml.load(yamlContent) as any;
    
    logger.info("📂 Loading config from new array structure", {
      client_id: clientId,
      config_path: yamlPath
    });
    
    // 2. Decrypt secrets
    const secretsPath = path.join(envsRepoPath, `clients/${clientId}/secrets.sops.yaml`);
    const sopsCmd = process.platform === "win32" 
      ? path.join(envsRepoPath, "tools/win64/sops.exe")
      : "sops";
      
    process.env.GPG_PASSPHRASE = gpgPassphrase;
    
    const decrypted = execSync(`${sopsCmd} -d --output-type json ${secretsPath}`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'] // Silenciar output
    });
    
    const secrets = JSON.parse(decrypted);
    
    // 3. 🔥 BUSCAR CONFIGURACIÓN EN ARRAYS
    const coreBackendConfig = yamlConfig.services?.find((s: any) => s.name === 'core-backend');
    const coreServicesConfig = yamlConfig.services?.find((s: any) => s.name === 'core-services');
    
    if (!coreBackendConfig) {
      throw new Error(`core-backend configuration not found in services array for client ${clientId}`);
    }
    
    // Buscar credenciales
    const coreBackendSecrets = secrets.services?.find((s: any) => s.name === 'core-backend')?.credentials || {};
    const coreServicesSecrets = secrets.services?.find((s: any) => s.name === 'core-services')?.credentials || {};
    
    // 4. Construir configuración final
    cachedConfig = {
      // Database - desde core-backend config
      pgHost: coreBackendConfig.database?.host || "localhost",
      pgPort: coreBackendConfig.database?.port || 5432,
      pgDatabase: coreBackendConfig.database?.name || "core_dev",
      pgUser: coreBackendSecrets.database?.username || "postgres",
      pgPassword: coreBackendSecrets.database?.password || "",
      pgMinConnections: coreBackendConfig.database?.pool?.min || 2,
      pgMaxConnections: coreBackendConfig.database?.pool?.max || 10,
      pgIdleTimeoutMillis: coreBackendConfig.database?.pool?.idle_timeout_millis || 30000,
      pgConnectionTimeoutMillis: coreBackendConfig.database?.pool?.connection_timeout_millis || 2000,

      // Auth - 🔥 IMPORTANTE: JWT viene de core-services!
      jwtSecret: coreServicesSecrets.jwt_secret || coreServicesSecrets.internal_jwt_secret || "",

      // Service identification
      tenantId: yamlConfig.tenant?.client_id || clientId,
      serviceName: coreBackendConfig.name || "core-backend",
      clientId: clientId,

      // Network
      backendPort: coreBackendConfig.port || 3000,
      backendHost: coreBackendConfig.host || "0.0.0.0",

      // Environment
      nodeEnv: (yamlConfig.tenant?.environment || "development") as any,
      logLevel: (coreBackendConfig.log_level || "info") as any
    };
    
    // Validar configuración crítica
    if (!cachedConfig.jwtSecret) {
      throw new Error("JWT secret not found in core-services credentials!");
    }
    
    if (!cachedConfig.pgPassword) {
      throw new Error("Database password not found in core-backend credentials!");
    }
    
    logger.info("✅ Configuration loaded successfully", {
      service_name: cachedConfig.serviceName,
      tenant_id: cachedConfig.tenantId,
      backend_port: cachedConfig.backendPort,
      database_host: cachedConfig.pgHost,
      config_source: "SOPS_ARRAY_STRUCTURE"
    });
    
    return cachedConfig;
    
  } catch (error) {
    logger.error("💥 Config loading failed", {
      error: error instanceof Error ? error.message : String(error),
      client_id: clientId
    });
    throw error;
  }
};

// Para compatibilidad con el código existente
export const getConfig = async (): Promise<EnvironmentConfig> => {
  return loadConfig();
};

export const getConfigSync = (): EnvironmentConfig => {
  return loadConfig();
};

// Default export para imports directos
export default getConfigSync();