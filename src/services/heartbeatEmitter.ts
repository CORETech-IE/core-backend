import axios from "axios";
import config from "../config/envConfig";
import os from "os";
import { getAuthToken } from "../utils/getToken";

let first = true;

export const startHeartbeat = () => {
  setInterval(async () => {
    try {
      const uptime = Math.floor(process.uptime());
      const memoryRssMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
      const heapUsedMb = Math.round(
        process.memoryUsage().heapUsed / 1024 / 1024
      );
      const cpuUsage = process.cpuUsage();
      const cpuUserMs = Math.round(cpuUsage.user / 1000);
      const cpuSystemMs = Math.round(cpuUsage.system / 1000);
      const hostname = os.hostname();
      const loadAvg = os.loadavg();
      const cpuLoad1m =
        loadAvg[0] > 0 ? parseFloat(loadAvg[0].toFixed(2)) : undefined;

      const metadata: Record<string, any> = {
        uptime_sec: uptime,
        memory_rss_mb: memoryRssMb,
        heap_used_mb: heapUsedMb,
        cpu_user_ms: cpuUserMs,
        cpu_system_ms: cpuSystemMs,
        hostname,
      };

      if (cpuLoad1m !== undefined) {
        metadata.cpu_load_1m = cpuLoad1m;
      }

      const payload = {
        client_id: config.tenantId,
        service: config.serviceName || "core_services",
        timestamp: new Date().toISOString(),
        status: first ? "STARTUP" : "OK",
        metadata,
      };

      if (first) {
        payload.status = "STARTUP";
        first = false;
      }

      const token = await getAuthToken();
      await axios.post(`${config.apiUrl}/heartbeat`, payload, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      console.log("✅ Heartbeat sent:", payload.status);
    } catch (err: any) {
      if (axios.isAxiosError(err)) {
        console.error("❌ Axios error:", err.response?.data || err.message);
      } else {
        console.error("❌ Unknown error:", err);
      }
    }
  }, 60000); //every 60 seconds
  console.log("Heartbeat emitter started, sending every 1 minute");
};
