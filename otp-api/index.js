const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

/** ---------- CONFIG ---------- **/
const PORT = Number(process.env.PORT || 3000);
const MAC_AUTH_DAYS = Number(process.env.MAC_AUTH_DAYS || 30);
const SESSION_TIMEOUT_SECONDS = Number(
  process.env.SESSION_TIMEOUT_SECONDS || MAC_AUTH_DAYS * 86400
);

const MUTLUCELL_URL = process.env.MUTLUCELL_URL || "https://smsgw.mutlucell.com/smsgw-ws/sndblkex";
const MUTLUCELL_KA = process.env.MUTLUCELL_KA;
const MUTLUCELL_PWD = process.env.MUTLUCELL_PWD;
const MUTLUCELL_ORG = "NETNUCLEUS";
const MUTLUCELL_CHARSET = process.env.MUTLUCELL_CHARSET || "turkish";

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "olives-admin-2024";
const DNS_LOG_RETENTION_DAYS = Number(process.env.DNS_LOG_RETENTION_DAYS || 90);
const DNS_LOG_CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000;

if (!MUTLUCELL_KA || !MUTLUCELL_PWD) {
  console.error("MUTLUCELL_KA veya MUTLUCELL_PWD eksik. /opt/otp-api/.env kontrol et.");
}

/** ---------- POSTGRES ---------- **/
const pool = new Pool({
  host: process.env.PGHOST || "localhost",
  port: Number(process.env.PGPORT || 5432),
  user: process.env.PGUSER || "radius",
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE || "wifidb",
});

/** ---------- DB MIGRATION ---------- **/
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS mac_auth (
        id SERIAL PRIMARY KEY,
        mac VARCHAR(50) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        authenticated_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_mac_auth_mac ON mac_auth(mac)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_mac_auth_time ON mac_auth(authenticated_at)`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS connection_logs (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(20),
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        mac VARCHAR(50),
        ip VARCHAR(50),
        requested_url TEXT,
        action VARCHAR(20) DEFAULT 'login',
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`
      ALTER TABLE connection_logs ADD COLUMN IF NOT EXISTS requested_url TEXT
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS dns_logs (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(20),
        mac VARCHAR(50),
        ip VARCHAR(50),
        domain VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_dns_logs_phone ON dns_logs(phone)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_dns_logs_domain ON dns_logs(domain)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_dns_logs_time ON dns_logs(created_at)`);

    console.log("DB migration OK");
  } catch (err) {
    console.error("DB migration error:", err.message);
  }
}

/** ---------- HELPERS ---------- **/
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function escapeXml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function normalizeTrPhone(raw) {
  let p = String(raw || "").trim();
  p = p.replace(/[^\d+]/g, "");
  if (p.startsWith("+")) p = p.slice(1);
  if (p.startsWith("0")) p = p.slice(1);
  if (p.startsWith("90")) return p;
  if (p.startsWith("5") && p.length === 10) return "90" + p;
  return p;
}

function sanitizeName(name) {
  if (!name) return null;
  return String(name)
    .trim()
    .replace(/[<>'"&]/g, "")
    .slice(0, 100);
}

function normalizeMac(mac) {
  if (!mac) return null;
  const cleaned = String(mac).trim().toUpperCase();
  if (cleaned.startsWith("$(") || cleaned.length < 6) return null;
  return cleaned;
}

function macAuthInterval() {
  return `${MAC_AUTH_DAYS} days`;
}

async function cleanupOldDnsLogs() {
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM dns_logs WHERE created_at < NOW() - INTERVAL '${DNS_LOG_RETENTION_DAYS} days'`
    );
    if (rowCount > 0) {
      console.log(`[CLEANUP] Deleted ${rowCount} dns_logs older than ${DNS_LOG_RETENTION_DAYS} days`);
    }
  } catch (err) {
    console.error("dns_logs cleanup error:", err.message);
  }
}

function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"] || req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ ok: false, error: "Yetkisiz" });
  }
  next();
}

async function setRadiusCredentials(username, password) {
  await pool.query(`DELETE FROM radcheck WHERE username = $1`, [username]);
  await pool.query(
    `INSERT INTO radcheck (username, attribute, op, value)
     VALUES ($1, 'Cleartext-Password', ':=', $2)`,
    [username, password]
  );

  await pool.query(
    `DELETE FROM radreply WHERE username = $1 AND attribute = 'Session-Timeout'`,
    [username]
  );
  await pool.query(
    `INSERT INTO radreply (username, attribute, op, value)
     VALUES ($1, 'Session-Timeout', ':=', $2)`,
    [username, String(SESSION_TIMEOUT_SECONDS)]
  );
}

async function sendSmsMutlucell({ toPhone, text }) {
  const phone = normalizeTrPhone(toPhone);

  const xml =
`<?xml version="1.0" encoding="UTF-8"?>
<smspack ka="${escapeXml(MUTLUCELL_KA)}" pwd="${escapeXml(MUTLUCELL_PWD)}" org="${escapeXml(MUTLUCELL_ORG)}" charset="${escapeXml(MUTLUCELL_CHARSET)}">
  <mesaj>
    <metin>${escapeXml(text)}</metin>
    <nums>${escapeXml(phone)}</nums>
  </mesaj>
</smspack>`;

  const resp = await axios.post(MUTLUCELL_URL, xml, {
    headers: { "Content-Type": "text/xml; charset=UTF-8" },
    timeout: 15000,
    validateStatus: () => true,
  });

  return {
    status: resp.status,
    body: typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data),
  };
}

/** ---------- BASIC HEALTH ---------- **/
app.get("/health", (req, res) => res.json({ ok: true }));

/** ---------- MAC CHECK (auto-login) ---------- **/
app.post("/otp/check-mac", async (req, res) => {
  try {
    const mac = normalizeMac(req.body.mac);
    if (!mac) {
      return res.json({ ok: false });
    }

    const { rows } = await pool.query(
      `SELECT phone, first_name, last_name FROM mac_auth
       WHERE mac = $1 AND authenticated_at > NOW() - INTERVAL '${macAuthInterval()}'
       ORDER BY authenticated_at DESC LIMIT 1`,
      [mac]
    );

    if (rows.length === 0) {
      return res.json({ ok: false });
    }

    const { phone, first_name, last_name } = rows[0];
    const username = phone;
    const password = generateOtp();

    await setRadiusCredentials(username, password);

    const requestedUrl = req.body.requestedUrl || null;
    await pool.query(
      `INSERT INTO connection_logs (phone, first_name, last_name, mac, ip, requested_url, action)
       VALUES ($1, $2, $3, $4, $5, $6, 'auto-login')`,
      [phone, first_name, last_name, mac, req.body.ip || null, requestedUrl]
    ).catch((err) => console.error("connection_logs insert:", err.message));

    console.log("[AUTO-LOGIN]", phone, first_name, last_name, mac);
    return res.json({ ok: true, username, password, firstName: first_name, lastName: last_name });
  } catch (err) {
    console.error("check-mac error:", err?.message || err);
    return res.json({ ok: false });
  }
});

/** ---------- OTP REQUEST ---------- **/
app.post("/otp/request", async (req, res) => {
  try {
    const { phone, firstName, lastName, kvkkAccepted, mac, ip } = req.body;

    if (!phone) {
      return res.status(400).json({ ok: false, error: "Telefon numarası gerekli" });
    }

    if (!firstName || firstName.trim().length < 2) {
      return res.status(400).json({ ok: false, error: "Ad en az 2 karakter olmalı" });
    }

    if (!lastName || lastName.trim().length < 2) {
      return res.status(400).json({ ok: false, error: "Soyad en az 2 karakter olmalı" });
    }

    if (!kvkkAccepted) {
      return res.status(400).json({ ok: false, error: "KVKK onayı gerekli" });
    }

    const normalized = normalizeTrPhone(phone);
    if (!normalized || normalized.length < 10) {
      return res.status(400).json({ ok: false, error: "Geçersiz telefon numarası" });
    }

    const sanitizedFirstName = sanitizeName(firstName);
    const sanitizedLastName = sanitizeName(lastName);

    const rl = await pool.query(
      `SELECT id FROM otp_requests
       WHERE phone = $1 AND created_at > NOW() - INTERVAL '60 seconds'
       ORDER BY id DESC LIMIT 1`,
      [normalized]
    );
    if (rl.rows.length > 0) {
      return res.status(429).json({ ok: false, error: "1 dakika bekleyip tekrar deneyin" });
    }

    const code = generateOtp();
    const expiresMinutes = 5;

    await pool.query(
      `INSERT INTO otp_requests (phone, code, first_name, last_name, kvkk_accepted, mac, ip, created_at, expires_at, used)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW() + INTERVAL '${expiresMinutes} minutes', false)`,
      [normalized, code, sanitizedFirstName, sanitizedLastName, true, mac || null, ip || null]
    );

    const smsText = `Merhaba ${sanitizedFirstName}, Olives Coffee WiFi kodun: ${code}\n5 dk gecerli.`;

    const smsResp = await sendSmsMutlucell({ toPhone: normalized, text: smsText });
    console.log("[SMS]", normalized, sanitizedFirstName, sanitizedLastName, smsResp.status, smsResp.body);

    if (smsResp.status >= 400) {
      return res.status(500).json({ ok: false, error: "SMS gönderilemedi" });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("otp/request error:", err?.message || err, err?.response?.data || "");
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- OTP VERIFY ---------- **/
app.post("/otp/verify", async (req, res) => {
  try {
    const { phone, code, mac, ip, requestedUrl } = req.body;
    if (!phone || !code) return res.status(400).json({ ok: false, error: "Telefon ve kod gerekli" });

    const normalized = normalizeTrPhone(phone);

    const { rows } = await pool.query(
      `SELECT id, first_name, last_name FROM otp_requests
       WHERE phone = $1 AND code = $2
         AND used = false
         AND expires_at > NOW()
       ORDER BY id DESC
       LIMIT 1`,
      [normalized, String(code).trim()]
    );

    if (rows.length === 0) {
      return res.status(400).json({ ok: false, error: "Kod geçersiz veya süresi dolmuş" });
    }

    const otpRecord = rows[0];
    const otpId = otpRecord.id;

    await pool.query(`UPDATE otp_requests SET used = true WHERE id = $1`, [otpId]);

    const username = normalized;
    const password = generateOtp();

    await setRadiusCredentials(username, password);

    await pool.query(
      `INSERT INTO wifi_users (phone, first_name, last_name, kvkk_accepted_at, last_login, login_count)
       VALUES ($1, $2, $3, NOW(), NOW(), 1)
       ON CONFLICT (phone) DO UPDATE SET
         first_name = EXCLUDED.first_name,
         last_name = EXCLUDED.last_name,
         last_login = NOW(),
         login_count = wifi_users.login_count + 1`,
      [normalized, otpRecord.first_name, otpRecord.last_name]
    );

    const normalizedMac = normalizeMac(mac);
    if (normalizedMac) {
      await pool.query(
        `DELETE FROM mac_auth WHERE mac = $1`,
        [normalizedMac]
      );
      await pool.query(
        `INSERT INTO mac_auth (mac, phone, first_name, last_name, authenticated_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [normalizedMac, normalized, otpRecord.first_name, otpRecord.last_name]
      );
    }

    await pool.query(
      `INSERT INTO connection_logs (phone, first_name, last_name, mac, ip, requested_url, action)
       VALUES ($1, $2, $3, $4, $5, $6, 'otp-login')`,
      [normalized, otpRecord.first_name, otpRecord.last_name, normalizedMac, ip || null, requestedUrl || null]
    ).catch((err) => console.error("connection_logs insert:", err.message));

    console.log("[LOGIN]", normalized, otpRecord.first_name, otpRecord.last_name, normalizedMac);

    return res.json({ ok: true, username, password });
  } catch (err) {
    console.error("otp/verify error:", err?.message || err, err?.response?.data || "");
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- ADMIN: Kullanıcı listesi ---------- **/
app.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT phone, first_name, last_name, last_login, login_count, kvkk_accepted_at
       FROM wifi_users
       ORDER BY last_login DESC
       LIMIT 500`
    );
    return res.json({ ok: true, users: rows });
  } catch (err) {
    console.error("admin/users error:", err?.message || err);
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- ADMIN: Bağlantı logları ---------- **/
app.get("/admin/logs", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    const phone = req.query.phone ? normalizeTrPhone(req.query.phone) : null;

    let query = `
      SELECT phone, first_name, last_name, mac, ip, requested_url, action, created_at
      FROM connection_logs
    `;
    const params = [];

    if (phone) {
      query += ` WHERE phone = $1`;
      params.push(phone);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`;
    params.push(limit);

    const { rows } = await pool.query(query, params);
    return res.json({ ok: true, logs: rows });
  } catch (err) {
    console.error("admin/logs error:", err?.message || err);
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- ADMIN: RADIUS accounting (eğer radacct varsa) ---------- **/
app.get("/admin/accounting", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);

    const { rows } = await pool.query(
      `SELECT
         r.username AS phone,
         w.first_name,
         w.last_name,
         r.callingstationid AS mac,
         r.framedipaddress AS ip,
         r.acctstarttime AS start_time,
         r.acctstoptime AS stop_time,
         r.acctinputoctets AS bytes_in,
         r.acctoutputoctets AS bytes_out,
         r.acctsessiontime AS session_seconds
       FROM radacct r
       LEFT JOIN wifi_users w ON w.phone = r.username
       ORDER BY r.acctstarttime DESC
       LIMIT $1`,
      [limit]
    );
    return res.json({ ok: true, accounting: rows });
  } catch (err) {
    if (err.message?.includes("does not exist")) {
      return res.json({ ok: true, accounting: [], note: "radacct tablosu bulunamadı - FreeRADIUS accounting ayarlarını kontrol edin" });
    }
    console.error("admin/accounting error:", err?.message || err);
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- DNS LOG INGEST (Mikrotik syslog → POST) ---------- **/
app.post("/log/dns", async (req, res) => {
  try {
    const token = req.headers["x-log-token"] || req.body.token;
    if (token !== ADMIN_TOKEN) {
      return res.status(401).json({ ok: false, error: "Yetkisiz" });
    }

    const { phone, mac, ip, domain } = req.body;
    if (!domain) {
      return res.status(400).json({ ok: false, error: "domain gerekli" });
    }

    const cleanDomain = String(domain)
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .slice(0, 255);

    if (!cleanDomain || cleanDomain.length < 3) {
      return res.status(400).json({ ok: false, error: "Geçersiz domain" });
    }

    await pool.query(
      `INSERT INTO dns_logs (phone, mac, ip, domain) VALUES ($1, $2, $3, $4)`,
      [phone ? normalizeTrPhone(phone) : null, normalizeMac(mac), ip || null, cleanDomain]
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error("log/dns error:", err?.message || err);
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- ADMIN: DNS logları (ziyaret edilen siteler) ---------- **/
app.get("/admin/dns-logs", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 200, 1000);
    const phone = req.query.phone ? normalizeTrPhone(req.query.phone) : null;
    const domain = req.query.domain ? String(req.query.domain).toLowerCase() : null;

    let query = `SELECT phone, mac, ip, domain, created_at FROM dns_logs WHERE 1=1`;
    const params = [];

    if (phone) {
      params.push(phone);
      query += ` AND phone = $${params.length}`;
    }
    if (domain) {
      params.push(`%${domain}%`);
      query += ` AND domain LIKE $${params.length}`;
    }

    params.push(limit);
    query += ` ORDER BY created_at DESC LIMIT $${params.length}`;

    const { rows } = await pool.query(query, params);
    return res.json({ ok: true, logs: rows });
  } catch (err) {
    console.error("admin/dns-logs error:", err?.message || err);
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- START ---------- **/
initDb().then(async () => {
  await cleanupOldDnsLogs();
  setInterval(cleanupOldDnsLogs, DNS_LOG_CLEANUP_INTERVAL_MS);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`OTP API listening on port ${PORT} (dns log retention: ${DNS_LOG_RETENTION_DAYS} days)`);
  });
});
