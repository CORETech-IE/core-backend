import { Request, Response, NextFunction } from "express";
import db from "../../config/db";
import logger from "../../utils/logger";

interface MetricEntry {
  metric_name: string;
  value: number;
  metadata?: Record<string, any>;
}

export const receiveMetrics = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { client_id, timestamp, service, metrics } = req.body;

    // Validate top-level structure
    if (
      typeof client_id !== "string" ||
      typeof timestamp !== "string" ||
      typeof service !== "string" ||
      !Array.isArray(metrics)
    ) {
      logger.warn("[/api/metrics] Invalid payload shape", { body: req.body });
      return res.status(400).json({ error: "Invalid request structure" });
    }

    // Parse and validate timestamp
    const ts = new Date(timestamp);
    if (isNaN(ts.getTime())) {
      return res.status(400).json({ error: "Invalid timestamp format" });
    }

    const validMetrics: {
      client_id: string;
      service: string;
      timestamp: Date;
      metric_name: string;
      value: number;
      metadata: any;
    }[] = [];

    for (const entry of metrics) {
      if (
        typeof entry.metric_name !== "string" ||
        typeof entry.value !== "number" ||
        isNaN(entry.value)
      ) {
        logger.warn("[/api/metrics] Skipping invalid metric entry", { entry });
        continue;
      }

      validMetrics.push({
        client_id,
        service,
        timestamp: ts,
        metric_name: entry.metric_name,
        value: entry.value,
        metadata: entry.metadata || null,
      });
    }

    if (validMetrics.length === 0) {
      return res.status(400).json({ error: "No valid metrics provided" });
    }

    const insertQuery = `
      INSERT INTO metrics (
        client_id, service, timestamp, metric_name, value, metadata
      ) VALUES 
      ${validMetrics
        .map(
          (_, i) =>
            `($${i * 6 + 1}, $${i * 6 + 2}, $${i * 6 + 3}, $${i * 6 + 4}, $${i * 6 + 5}, $${i * 6 + 6})`
        )
        .join(",\n")}
    `;

    const insertValues = validMetrics.flatMap((m) => [
      m.client_id,
      m.service,
      m.timestamp,
      m.metric_name,
      m.value,
      JSON.stringify(m.metadata),
    ]);

    // Debug logs
    logger.info("[/api/metrics] Insert query and values", {
      query: insertQuery,
      values: insertValues
    });

    // Check for undefined values
    for (let i = 0; i < insertValues.length; i++) {
      if (typeof insertValues[i] === "undefined") {
        console.error(`🚨 Undefined value at index ${i}:`, insertValues[i]);
      }
    }

    await db.query(insertQuery, insertValues);

    return res.status(200).json({ inserted: validMetrics.length });
  } catch (err: any) {
    let errorMsg = "Unknown error";
    let errorStack = undefined;
    if (err instanceof Error) {
      errorMsg = err.message;
      errorStack = err.stack;
    }

    logger.error("[/api/metrics] Internal error", {
      error: errorMsg,
      stack: errorStack,
    });

    console.error("[/api/metrics] Raw error:", err); // Esto va a consola

    return res.status(500).json({ error: "Internal server error" });
  }
};
