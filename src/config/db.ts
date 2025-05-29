import { Pool } from "pg";
import envConfig from "../config/envConfig";

const pool = new Pool({
  host: envConfig.pgHost,
  port: envConfig.pgPort,
  database: envConfig.pgDatabase,
  user: envConfig.pgUser,
  password: envConfig.pgPassword,
});

export default {
  query: (text: string, params?: any[]) => pool.query(text, params)
};
