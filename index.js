require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

app.use(helmet());
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true, limit: "256kb" }));
app.use(express.raw({ type: "*/*", limit: "256kb" }));

const ipaddr = require("ipaddr.js");

// --- Runtime configuration (mutable via admin endpoints) ---
const config = {
  // "none" | "basic" | "token" | "both"
  authMode: "none",
  // Credentials used to protect the *webhook* endpoint (not admin)
  webhookBasicUser: "",
  webhookBasicPass: "",
  webhookToken: "",
  // HTTP status code the webhook endpoint returns
  responseStatus: 200,
  // Optional static JSON body to return
  responseBody: { ok: true },
  // Whitelist: IPs/CIDRs and required headers (empty = allow all)
  allowedIPs: [],
  // Array of { name, value } — request must match ALL entries
  requiredHeaders: [],
  // Rate limiting (0 = disabled)
  rateLimitPerIp: 10,
  rateLimitGlobal: 30,
};

// --- Rate limiting (reads from config dynamically) ---

const perIpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: () => config.rateLimitPerIp || 0,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests from this IP, try again later" },
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: () => config.rateLimitGlobal || 0,
  keyGenerator: () => "global",
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests globally, try again later" },
});

app.use("/webhook", globalLimiter, perIpLimiter);

// --- Request log (kept in memory) ---
const logs = [];
const MAX_LOGS = 500;

function pushLog(entry) {
  logs.push(entry);
  if (logs.length > MAX_LOGS) logs.shift();
}

// --- Helpers ---

function parseBasicAuth(header) {
  if (!header || !header.startsWith("Basic ")) return null;
  const decoded = Buffer.from(header.slice(6), "base64").toString();
  const colon = decoded.indexOf(":");
  if (colon === -1) return null;
  return { user: decoded.slice(0, colon), pass: decoded.slice(colon + 1) };
}

function checkAdminAuth(req, res) {
  const creds = parseBasicAuth(req.headers.authorization);
  if (
    !creds ||
    creds.user !== process.env.ADMIN_USERNAME ||
    creds.pass !== process.env.ADMIN_PASSWORD
  ) {
    res.set("WWW-Authenticate", 'Basic realm="Admin"');
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

function checkWhitelist(req, res) {
  // IP whitelist check
  if (config.allowedIPs.length > 0) {
    const rawIp = req.ip || req.socket.remoteAddress;
    let clientAddr;
    try {
      clientAddr = ipaddr.process(rawIp);
    } catch {
      res.status(403).json({ error: "Forbidden" });
      return false;
    }

    const ipAllowed = config.allowedIPs.some((entry) => {
      try {
        if (entry.includes("/")) {
          const [addr, bits] = ipaddr.parseCIDR(entry);
          return clientAddr.match(addr, bits);
        }
        return clientAddr.toString() === ipaddr.process(entry).toString();
      } catch {
        return false;
      }
    });

    if (!ipAllowed) {
      res.status(403).json({ error: "Forbidden: IP not allowed" });
      return false;
    }
  }

  // Required headers check
  if (config.requiredHeaders.length > 0) {
    const headersOk = config.requiredHeaders.every(({ name, value }) => {
      const actual = req.headers[name.toLowerCase()];
      return actual !== undefined && actual === value;
    });

    if (!headersOk) {
      res.status(403).json({ error: "Forbidden: required header missing or invalid" });
      return false;
    }
  }

  return true;
}

function checkWebhookAuth(req, res) {
  const mode = config.authMode;
  if (mode === "none") return true;

  const basicOk = () => {
    const creds = parseBasicAuth(req.headers.authorization);
    return (
      creds &&
      creds.user === config.webhookBasicUser &&
      creds.pass === config.webhookBasicPass
    );
  };

  const tokenOk = () => {
    const header = req.headers.authorization || "";
    return header === `Bearer ${config.webhookToken}`;
  };

  let passed = false;
  if (mode === "basic") passed = basicOk();
  else if (mode === "token") passed = tokenOk();
  else if (mode === "both") passed = basicOk() || tokenOk();

  if (!passed) {
    res.status(401).json({ error: "Unauthorized" });
    return false;
  }
  return true;
}

// --- Webhook endpoint (catches all methods) ---

app.all("/webhook", (req, res) => {
  if (!checkWhitelist(req, res)) return;
  if (!checkWebhookAuth(req, res)) return;

  const entry = {
    timestamp: new Date().toISOString(),
    method: req.method,
    path: req.originalUrl,
    headers: req.headers,
    body: req.body,
  };

  pushLog(entry);
  console.log("--- Incoming webhook ---");
  console.log(JSON.stringify(entry, null, 2));

  res.status(config.responseStatus).json(config.responseBody);
});

// --- Admin endpoints (all require basic auth from .env) ---

// GET /admin/config – view current config
app.get("/admin/config", (req, res) => {
  if (!checkAdminAuth(req, res)) return;
  res.json(config);
});

// PATCH /admin/config – update config fields
app.patch("/admin/config", (req, res) => {
  if (!checkAdminAuth(req, res)) return;

  const {
    authMode,
    webhookBasicUser,
    webhookBasicPass,
    webhookToken,
    responseStatus,
    responseBody,
    allowedIPs,
    requiredHeaders,
    rateLimitPerIp,
    rateLimitGlobal,
  } = req.body;

  if (authMode !== undefined) {
    if (!["none", "basic", "token", "both"].includes(authMode)) {
      return res
        .status(400)
        .json({ error: "authMode must be none|basic|token|both" });
    }
    config.authMode = authMode;
  }
  if (webhookBasicUser !== undefined) config.webhookBasicUser = webhookBasicUser;
  if (webhookBasicPass !== undefined) config.webhookBasicPass = webhookBasicPass;
  if (webhookToken !== undefined) config.webhookToken = webhookToken;
  if (responseStatus !== undefined) {
    const code = Number(responseStatus);
    if (isNaN(code) || code < 100 || code > 599) {
      return res
        .status(400)
        .json({ error: "responseStatus must be 100-599" });
    }
    config.responseStatus = code;
  }
  if (responseBody !== undefined) config.responseBody = responseBody;
  if (allowedIPs !== undefined) {
    if (!Array.isArray(allowedIPs) || !allowedIPs.every((e) => typeof e === "string")) {
      return res
        .status(400)
        .json({ error: "allowedIPs must be an array of IP/CIDR strings" });
    }
    config.allowedIPs = allowedIPs;
  }
  if (requiredHeaders !== undefined) {
    if (
      !Array.isArray(requiredHeaders) ||
      !requiredHeaders.every((e) => e && typeof e.name === "string" && typeof e.value === "string")
    ) {
      return res
        .status(400)
        .json({ error: 'requiredHeaders must be an array of { name, value } objects' });
    }
    config.requiredHeaders = requiredHeaders;
  }
  if (rateLimitPerIp !== undefined) {
    const val = Number(rateLimitPerIp);
    if (isNaN(val) || val < 0) {
      return res.status(400).json({ error: "rateLimitPerIp must be >= 0 (0 = disabled)" });
    }
    config.rateLimitPerIp = val;
  }
  if (rateLimitGlobal !== undefined) {
    const val = Number(rateLimitGlobal);
    if (isNaN(val) || val < 0) {
      return res.status(400).json({ error: "rateLimitGlobal must be >= 0 (0 = disabled)" });
    }
    config.rateLimitGlobal = val;
  }

  console.log("Config updated:", JSON.stringify(config, null, 2));
  res.json(config);
});

// GET /admin/logs – view captured requests
app.get("/admin/logs", (req, res) => {
  if (!checkAdminAuth(req, res)) return;
  res.json(logs);
});

// DELETE /admin/logs – clear captured requests
app.delete("/admin/logs", (req, res) => {
  if (!checkAdminAuth(req, res)) return;
  logs.length = 0;
  res.json({ cleared: true });
});

// --- Start ---

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Webhook test server running on port ${PORT}`);
  console.log(`  Webhook endpoint:  POST /webhook`);
  console.log(`  Admin config:      GET|PATCH /admin/config`);
  console.log(`  Admin logs:        GET|DELETE /admin/logs`);
});
