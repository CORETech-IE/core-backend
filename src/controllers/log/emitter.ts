import { Request, Response } from "express";
import { sendLog } from "../../services/logEmitter";
import { v4 as uuidv4 } from "uuid";
import logger from "../../utils/logger";
import db from "../../config/db";

export const generateLogEmitter = async (req: Request, res: Response) => {
  const {
    client,
    service,
    level,
    message,
    tags = [],
    context = {},
    qos = 0,
    trace_id,
  } = req.body;

  if (!client || !service || !level || !message) {
    return res.status(400).json({
      error: "Missing required fields: client, service, level, message",
    });
  }

  try {
    const finalTraceId = trace_id || uuidv4();
    const timestamp = new Date();

    // Log to MQTT (optional, still useful)
    sendLog({
      clientName: client,
      service,
      level,
      message,
      tags,
      context,
      qos,
      trace_id: finalTraceId
    });

    // Log to PostgreSQL
    await db.query(
      `INSERT INTO logs (
        client_id, service, timestamp, level, message, tags, metadata, trace_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        client,
        service,
        timestamp,
        level,
        message,
        tags,
        JSON.stringify(context || {}),
        finalTraceId
      ]
    );

    return res.status(200).json({
      status: "Log emitted and saved",
      trace_id: finalTraceId
    });
  } catch (error) {
    logger.error("[generateLogEmitter] Failed to emit/save log", { error });
    return res.status(500).json({
      error: "Internal error while emitting log"
    });
  }
};
