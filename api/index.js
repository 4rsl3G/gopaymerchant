const express = require("express");
const axios = require("axios");
const path = require("path");
const helmet = require("helmet");
const compression = require("compression");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();

// =====================
// CONFIG
// =====================
const BASE_URL = process.env.UPSTREAM_BASE || "https://api.gobiz.co.id";

// Strict allowlist (anti open-proxy abuse)
const ALLOWED = new Set([
  "/goid/login/request",
  "/goid/token",
  "/v1/merchants/search",
  "/journals/search",
]);

function baseHeaders({ uniqueId, userAgent }) {
  return {
    "Content-Type": "application/json",
    Accept: "application/json, text/plain, */*",
    "Accept-Language": "id",
    Origin: "https://portal.gofoodmerchant.co.id",
    Referer: "https://portal.gofoodmerchant.co.id/",
    "Authentication-Type": "go-id",
    "Gojek-Country-Code": "ID",
    "Gojek-Timezone": "Asia/Jakarta",
    "X-Appid": "go-biz-web-dashboard",
    "X-Appversion": "platform-v3.97.0-b986b897",
    "X-Deviceos": "Web",
    "X-Phonemake": "Windows 10 64-bit",
    "X-Phonemodel": "Chrome 143.0.0.0 on Windows 10 64-bit",
    "X-Platform": "Web",
    "X-Uniqueid": uniqueId || "public",
    "X-User-Type": "merchant",
    "User-Agent": userAgent || "Mozilla/5.0 (GoBizProxy)",
  };
}

function normalizeEndpoint(ep) {
  if (!ep || typeof ep !== "string") return null;
  if (!ep.startsWith("/")) return null;
  return ep.split("?")[0];
}

function pickUpstreamErr(resp) {
  const msg =
    resp?.data?.message ||
    resp?.data?.error ||
    (typeof resp?.data === "string" ? resp.data : null) ||
    `HTTP_${resp?.status}`;
  return msg;
}

const ax = axios.create({
  timeout: Number(process.env.UPSTREAM_TIMEOUT_MS || 30000),
  validateStatus: () => true,
});

// =====================
// MIDDLEWARE
// =====================
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);
app.use(compression());
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: "300kb" }));
app.use(express.urlencoded({ extended: true }));

// IMPORTANT: On Vercel, bundle-safe paths must live under /api
const ROOT = __dirname; // /var/task/api in Vercel

app.set("views", path.join(ROOT, "views"));
app.set("view engine", "ejs");
app.use("/public", express.static(path.join(ROOT, "public")));

// Rate limit (public)
const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_PER_MIN || 60),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(publicLimiter);

// =====================
// PAGES
// =====================
app.get("/", (req, res) => res.render("index", { baseUrl: BASE_URL }));
app.get("/docs", (req, res) => res.render("docs", { baseUrl: BASE_URL }));

// =====================
// CORE PROXY (safe)
// =====================
async function upstream({ endpoint, method, body, headers }) {
  const url = `${BASE_URL}${endpoint}`;
  const resp = await ax.request({ method, url, data: body, headers });
  return resp;
}

function ensureSession(req) {
  const session = req.body?.session || {};
  const uniqueId = String(session.uniqueId || "").trim() || crypto.randomUUID();
  const userAgent = String(session.userAgent || "").trim() || "Mozilla/5.0 (GoBizProxy)";
  return { uniqueId, userAgent };
}

// =====================
// API ROUTES
// =====================

// Raw proxy (advanced)
app.post("/api/proxy", async (req, res) => {
  try {
    const endpoint = normalizeEndpoint(req.body?.endpoint);
    const method = String(req.body?.method || "POST").toUpperCase();
    const body = req.body?.body ?? {};
    const accept = req.body?.accept || null;
    const bearer = req.body?.bearer || null;

    if (!endpoint) return res.status(400).json({ error: "INVALID_ENDPOINT" });
    if (!ALLOWED.has(endpoint)) return res.status(403).json({ error: "ENDPOINT_NOT_ALLOWED", endpoint });
    if (!["POST", "GET"].includes(method)) return res.status(405).json({ error: "METHOD_NOT_ALLOWED" });

    const session = ensureSession(req);

    const headers = {
      ...baseHeaders(session),
      ...(accept ? { Accept: accept } : {}),
      Authorization: bearer ? `Bearer ${bearer}` : "Bearer",
    };

    const resp = await upstream({ endpoint, method, body, headers });
    return res.status(resp.status).json(resp.data);
  } catch (e) {
    return res.status(500).json({ error: "PROXY_ERROR", message: e?.message || "UNKNOWN_ERROR" });
  }
});

// OTP request (returns REAL otp_token)
app.post("/api/otp/request", async (req, res) => {
  try {
    const phone = String(req.body?.phone || "").trim();
    const countryCode = String(req.body?.countryCode || "62").trim();
    if (!phone) return res.status(400).json({ error: "PHONE_REQUIRED" });

    const session = ensureSession(req);

    const endpoint = "/goid/login/request";
    const body = {
      client_id: "go-biz-web-new",
      phone_number: phone,
      country_code: countryCode || "62",
    };

    const headers = { ...baseHeaders(session), Authorization: "Bearer" };

    const resp = await upstream({ endpoint, method: "POST", body, headers });
    if (resp.status < 200 || resp.status >= 300) {
      return res.status(resp.status).json({
        error: "OTP_REQUEST_FAILED",
        message: pickUpstreamErr(resp),
        data: resp.data || null,
      });
    }

    return res.status(200).json(resp.data);
  } catch (e) {
    return res.status(500).json({ error: "OTP_REQUEST_ERROR", message: e?.message || "UNKNOWN_ERROR" });
  }
});

// OTP verify (UI sends otpToken automatically; user only inputs OTP)
app.post("/api/otp/verify", async (req, res) => {
  try {
    const otp = String(req.body?.otp || "").trim();
    const otpToken = String(req.body?.otpToken || req.headers["x-otp-token"] || "").trim();
    if (!otp) return res.status(400).json({ error: "OTP_REQUIRED" });
    if (!otpToken) return res.status(400).json({ error: "OTP_TOKEN_REQUIRED" });

    const session = ensureSession(req);

    const endpoint = "/goid/token";
    const body = {
      client_id: "go-biz-web-new",
      grant_type: "otp",
      data: { otp, otp_token: otpToken },
    };

    const headers = { ...baseHeaders(session), Authorization: "Bearer" };

    const resp = await upstream({ endpoint, method: "POST", body, headers });
    if (resp.status < 200 || resp.status >= 300) {
      return res.status(resp.status).json({
        error: "OTP_VERIFY_FAILED",
        message: pickUpstreamErr(resp),
        data: resp.data || null,
      });
    }

    return res.status(200).json(resp.data);
  } catch (e) {
    return res.status(500).json({ error: "OTP_VERIFY_ERROR", message: e?.message || "UNKNOWN_ERROR" });
  }
});

// Merchant search (needs bearer)
app.post("/api/merchant/search", async (req, res) => {
  try {
    const bearer = String(req.body?.bearer || "").trim();
    if (!bearer) return res.status(400).json({ error: "ACCESS_TOKEN_REQUIRED" });

    const session = ensureSession(req);
    const endpoint = "/v1/merchants/search";
    const body = { from: 0, to: 1, _source: ["id", "name"] };
    const headers = { ...baseHeaders(session), Authorization: `Bearer ${bearer}` };

    const resp = await upstream({ endpoint, method: "POST", body, headers });
    return res.status(resp.status).json(resp.data);
  } catch (e) {
    return res.status(500).json({ error: "MERCHANT_ERROR", message: e?.message || "UNKNOWN_ERROR" });
  }
});

// Mutasi (needs bearer + merchantId + date)
app.post("/api/mutasi", async (req, res) => {
  try {
    const bearer = String(req.body?.bearer || "").trim();
    const merchantId = String(req.body?.merchantId || "").trim();
    const dateYmd = String(req.body?.dateYmd || "").trim();
    const size = Math.max(1, Math.min(200, Number(req.body?.size || 50)));

    if (!bearer) return res.status(400).json({ error: "ACCESS_TOKEN_REQUIRED" });
    if (!merchantId) return res.status(400).json({ error: "MERCHANT_ID_REQUIRED" });
    if (!dateYmd) return res.status(400).json({ error: "DATE_REQUIRED" });

    const session = ensureSession(req);

    const fromISO = `${dateYmd}T00:00:00+07:00`;
    const toISO = `${dateYmd}T23:59:59+07:00`;

    const endpoint = "/journals/search";
    const body = {
      from: 0,
      size,
      sort: { time: { order: "desc" } },
      included_categories: { incoming: ["transaction_share", "action"] },
      query: [
        {
          op: "and",
          clauses: [
            { field: "metadata.transaction.merchant_id", op: "equal", value: merchantId },
            { field: "metadata.transaction.transaction_time", op: "gte", value: fromISO },
            { field: "metadata.transaction.transaction_time", op: "lte", value: toISO },
          ],
        },
      ],
    };

    const headers = {
      ...baseHeaders(session),
      Authorization: `Bearer ${bearer}`,
      Accept: "application/json, application/vnd.journal.v1+json",
    };

    const resp = await upstream({ endpoint, method: "POST", body, headers });
    return res.status(resp.status).json(resp.data);
  } catch (e) {
    return res.status(500).json({ error: "MUTASI_ERROR", message: e?.message || "UNKNOWN_ERROR" });
  }
});

// =====================
// LOCAL DEV
// =====================
if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log("Listening on http://localhost:" + port));
}

module.exports = app;
