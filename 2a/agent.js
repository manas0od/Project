const WebSocket = require("ws");
const fs = require("fs");

const BASE_URL =
  "wss://claude-freedom-bridge.manasodvaigaod.workers.dev/connect";

const TOKEN_FILE = `${process.env.HOME}/.cfb/bridge.token`;

if (!fs.existsSync(TOKEN_FILE)) {
  console.error("CFB token file not found.");
  process.exit(1);
}

const TOKEN = fs.readFileSync(TOKEN_FILE, "utf8").trim();

if (!TOKEN) {
  console.error("CFB token file is empty.");
  process.exit(1);
}

// ---------- optional command execution (OFF unless ~/.cfb/config.json enables it) ----------

const execModule = require("./agent-exec");

let execConfig = execModule.loadConfig({
  file: process.env.CFB_CONFIG || undefined
});
let execApprover = null;

if (execConfig.enabled) {
  execApprover = execModule.createTtyApprover();

  if (!execApprover) {
    // Approval must come from a human at this device's keyboard. Without a
    // terminal there is nobody to ask, so fail closed.
    execConfig = {
      enabled: false,
      reason: "stdin is not an interactive terminal, so commands cannot be approved"
    };
  }
}

let execManager = null;

function sendToWorker(message) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
    return true;
  }

  return false;
}

execManager = execModule.createExecManager({
  config: execConfig,
  approver: execApprover,
  send: sendToWorker,
  log: (line) => console.log(`[exec] ${line}`),
  secrets: [TOKEN]
});

if (execConfig.enabled) {
  console.log(
    `Command execution: ENABLED (workspace roots: ${execConfig.roots.join(", ")}). ` +
    "Every command needs your approval in this terminal."
  );
} else {
  console.log(`Command execution: DISABLED (${execConfig.reason}).`);
}

let ws = null;
let reconnectTimer = null;
let heartbeatTimer = null;
let stopped = false;
let reconnectDelay = 2000;
const startedAt = Date.now();

// Heartbeat: the Worker only answers pings that carry a string "id".
// If no pong arrives within PONG_TIMEOUT_MS the connection is treated as dead.
const HEARTBEAT_MS = 20000;
const PONG_TIMEOUT_MS = 60000;
let lastPongAt = 0;
let pingCounter = 0;

function connect() {
  if (stopped) return;

  console.log("Connecting to CFB...");

  ws = new WebSocket(BASE_URL, {
    headers: {
      Authorization: `Bearer ${TOKEN}`
    },
    handshakeTimeout: 15000
  });

  ws.on("open", () => {
    console.log("Connected to CFB.");
    reconnectDelay = 2000;

    lastPongAt = Date.now();
    clearInterval(heartbeatTimer);

    heartbeatTimer = setInterval(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;

      if (Date.now() - lastPongAt > PONG_TIMEOUT_MS) {
        console.error("No heartbeat reply from CFB; reconnecting.");
        ws.terminate();
        return;
      }

      pingCounter += 1;
      ws.send(JSON.stringify({ type: "ping", id: `a${pingCounter}` }));
    }, HEARTBEAT_MS);

    // Tell the Worker what we remember so results survive reconnects.
    if (execConfig.enabled) {
      sendToWorker({ type: "exec_sync", jobs: execManager.snapshotAll() });
    }
  });

  ws.on("message", async (raw) => {
    let message;

    try {
      message = JSON.parse(raw.toString());
    } catch {
      console.error("Received invalid JSON.");
      return;
    }

    if (message.type === "connected") {
      console.log("Handshake successful. Protocol:", message.protocol);
      return;
    }

    if (message.type === "pong") {
      lastPongAt = Date.now();
      return;
    }

    if (message.type === "exec_request") {
      execManager.handleRequest(message);
      return;
    }

    if (message.type === "exec_cancel") {
      execManager.handleCancel(message);
      return;
    }

    if (message.type !== "request") {
      console.log("Unknown message:", message.type);
      return;
    }

    const requestId = message.request_id;
    const action = message.action;
    const payload = message.payload || {};

    let result;

    try {
      if (action === "status") {
        result = {
          ok: true,
          status: "online",
          platform: process.platform,
          architecture: process.arch,
          uptime_seconds: Math.floor((Date.now() - startedAt) / 1000)
        };
      } else if (action === "echo") {
        result = {
          ok: true,
          message: String(payload.message ?? "")
        };
      } else {
        result = {
          ok: false,
          error: "Unsupported action"
        };
      }
    } catch (error) {
      result = {
        ok: false,
        error: String(error.message || error)
      };
    }

    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: "response",
        request_id: requestId,
        result
      }));
    }
  });

  ws.on("error", (error) => {
    console.error("WebSocket error:", error.message);
  });

  ws.on("close", (code, reason) => {
    console.log(
      "Disconnected:",
      code,
      reason.toString()
    );

    clearInterval(heartbeatTimer);
    heartbeatTimer = null;

    if (!stopped) {
      console.log(`Reconnecting in ${reconnectDelay / 1000}s...`);

      reconnectTimer = setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 30000);
    }
  });
}

function shutdown() {
  if (stopped) return;

  stopped = true;
  clearTimeout(reconnectTimer);
  clearInterval(heartbeatTimer);

  execManager.shutdown();

  if (ws) ws.close();

  console.log("CFB agent stopped.");
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

connect();
