import mqtt, { MqttClient, IClientPublishOptions, PacketCallback } from 'mqtt';
import { v4 as uuidv4 } from 'uuid';
import config from '../config/config.json'; // Adjust the path to your config file
import os from 'os';

//const brokerUrl = 'mqtt://localhost:1883';
// import the mqtt broker url from the config file
const brokerUrl = config.mqttBrokerUrl;

const options = {
    clientId: 'logEmitter_' + Math.random().toString(16).slice(2),
    clean: true
};

// Cliente real o mock
let client: MqttClient;

try {
    const realClient = mqtt.connect(brokerUrl, options);
    realClient.on('connect', () => {
        console.log('[MQTT] Connected to broker.');
    });
    client = realClient;
} catch (err) {
    console.warn('[MQTT] Broker not available. Fallback to console logging.');

    client = {
        publish: (
            topic: string,
            message: string | Buffer,
            opts?: IClientPublishOptions,
            callback?: PacketCallback
        ) => {
            console.log(`[FAKE MQTT] Would publish to "${topic}" with payload:`);
            console.log(message?.toString?.() ?? message);
            if (callback) callback();
            return client;
        }
    } as unknown as MqttClient;
}

// Log payload type
interface LogPayload {
    clientName: string;
    service: string;
    level: 'debug' | 'info' | 'warn' | 'error' | 'critical';
    message: string;
    tags?: string[];
    context?: Record<string, any>;
    qos?: 0 | 1 | 2;
    hostname?: string;
    trace_id?: string;
}

// Core log emitter
export const sendLog = ({
    clientName,
    service,
    level,
    message,
    tags = [],
    context = {},
    qos = 0,
    hostname = os.hostname(),
    trace_id = uuidv4()
}: LogPayload): void => {
    const topic = `logs/${clientName}/${service}/${level}`;

    const payload = {
        timestamp: new Date().toISOString(),
        client: clientName,
        service,
        level,
        message,
        hostname,
        tags,
        trace_id,
        context
    };

    client.publish(topic, JSON.stringify(payload), { qos }, (err?: Error) => {
        if (err) {
            console.error(`[MQTT] Failed to publish log (${level}):`, err);
        }
    });
};
