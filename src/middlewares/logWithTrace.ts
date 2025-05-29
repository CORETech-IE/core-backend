import { Request } from "express";
import { v4 as uuidv4 } from "uuid";
import job_logger from "./job_logger";
import axios from "axios";
import { getInternalToken } from "../config/internalToken";

// Read internal token from config (for authenticated /emit-log calls)
const internalToken = getInternalToken();

interface LogData {
  job_type: string;                  // Type of job (e.g., PDF, EMAIL, SYSTEM)
  action: string;                   // What action was performed (e.g., GENERATED, FAILED)
  data?: Record<string, any>;       // Optional payload data
  status?: string;                  // Optional status (e.g., SUCCESS, ERROR)
  level?: "info" | "warn" | "error";// Log level
  trace_id?: string;                // Trace identifier (auto-generated if missing)
  emit?: boolean;                   // Whether to also emit to MQTT
}

export const logWithTrace = async (
  req: Request,
  log: LogData
): Promise<string> => {
  const user = (req as any).user?.username || "anonymous";
  const trace_id = log.trace_id || (req as any).trace_id || uuidv4();
  const level = log.level || "info";

  // Store trace_id in request for downstream access
  (req as any).trace_id = trace_id;

  const payload = {
    job_type: log.job_type,
    action: log.action,
    user,
    trace_id,
    status: log.status || "N/A",
    data: log.data || {},
  };

  // ✅ Always log locally (disk + console via winston)
  job_logger[level](payload);

  // 📡 Optionally emit log to MQTT via secured HTTP POST
  if (log.emit) {
    try {
      await axios.post(
        "http://localhost:3000/emit-log",
        {
          client: "core_services",
          service: log.job_type,
          level: level,
          message: `${log.job_type}:${log.action}`,
          tags: [log.status || ""],
          context: payload.data,
          trace_id,
        },
        {
          headers: { Authorization: `Bearer ${internalToken}` },
        }
      );
    } catch (err) {
      job_logger.warn({
        job_type: "LOG",
        action: "EMIT_FAILED",
        level: "warn",
        data: { error: err instanceof Error ? err.message : String(err) },
      });
    }
  }

  return trace_id;
};
