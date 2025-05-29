import axios from "axios";
import config from "../config/envConfig";

let cachedToken = "";
let tokenExpiresAt = 0;

export async function getAuthToken(): Promise<string> {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt) {
    return cachedToken;
  }

  try {
    const response = await axios.post(`${config.authUrl}/login`, {
      username: config.authUsername,
      password: config.authPassword,
    });

    if (response.status !== 200 || !response.data?.token) {
      throw new Error("Invalid response from auth server");
    }

    cachedToken = response.data.token;
    const expiresIn = response.data.expiresIn || 3600; // en segundos
    tokenExpiresAt = now + expiresIn * 1000 - 10000; // 10s de margen

    return cachedToken;
  } catch (err: any) {
    console.error("❌ Failed to get auth token:", err.response?.data || err.message);
    throw new Error("Authentication failed");
  }
}
