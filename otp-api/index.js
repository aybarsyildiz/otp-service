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

const MUTLUCELL_URL = process.env.MUTLUCELL_URL || "https://smsgw.mutlucell.com/smsgw-ws/sndblkex";
const MUTLUCELL_KA = process.env.MUTLUCELL_KA;
const MUTLUCELL_PWD = process.env.MUTLUCELL_PWD;
const MUTLUCELL_ORG = "NETNUCLEUS";
const MUTLUCELL_CHARSET = process.env.MUTLUCELL_CHARSET || "turkish"; // turkish | unicode vs

if (!MUTLUCELL_KA || !MUTLUCELL_PWD) {
  console.error("❌ MUTLUCELL_KA veya MUTLUCELL_PWD eksik. /opt/otp-api/.env kontrol et.");
}

/** ---------- POSTGRES ---------- **/
const pool = new Pool({
  host: process.env.PGHOST || "localhost",
  port: Number(process.env.PGPORT || 5432),
  user: process.env.PGUSER || "radius",
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE || "wifidb",
});

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

/**
 * TR normalize:
 * - "5xx..."  -> "90xxxxxxxxxx"
 * - "0(5xx)"  -> "90xxxxxxxxxx"
 * - "+90..."  -> "90..."
 * - boşluk, parantez, tire temizlenir
 */
function normalizeTrPhone(raw) {
  let p = String(raw || "").trim();
  p = p.replace(/[^\d+]/g, ""); // sadece digit + kalsın
  if (p.startsWith("+")) p = p.slice(1);
  if (p.startsWith("0")) p = p.slice(1);
  if (p.startsWith("90")) return p;
  if (p.startsWith("5") && p.length === 10) return "90" + p;
  return p; // ne geldiyse (en azından bozmuyoruz)
}

/**
 * İsim/soyisim temizleme
 */
function sanitizeName(name) {
  if (!name) return null;
  return String(name)
    .trim()
    .replace(/[<>'"&]/g, "") // Basit XSS koruması
    .slice(0, 100); // Max 100 karakter
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

  // Mutlucell çoğu zaman text/plain / xml döner. Biz loglayalım:
  return {
    status: resp.status,
    body: typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data),
  };
}

/** ---------- BASIC HEALTH ---------- **/
app.get("/health", (req, res) => res.json({ ok: true }));

/** ---------- OTP REQUEST ---------- **/
app.post("/otp/request", async (req, res) => {
  try {
    const { phone, firstName, lastName, kvkkAccepted, mac, ip } = req.body;

    // Validasyonlar
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

    // basit rate limit: aynı telefona 60 sn içinde tekrar yollama
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

    // SMS content
    const smsText = `Olives Coffee WiFi kodun: ${code}\n5 dk geçerli.`;

    // Mutlucell gönder
    const smsResp = await sendSmsMutlucell({ toPhone: normalized, text: smsText });
    console.log("[SMS]", normalized, smsResp.status, smsResp.body);

    // İstersen response'u DB'ye de yazabiliriz ama şimdilik log yeter
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
    const { phone, code } = req.body;
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

    // RADIUS: username=phone, password=tek seferlik üretelim
    const username = normalized;
    const password = generateOtp();

    await pool.query(`DELETE FROM radcheck WHERE username = $1`, [username]);

    await pool.query(
      `INSERT INTO radcheck (username, attribute, op, value)
       VALUES ($1, 'Cleartext-Password', ':=', $2)`,
      [username, password]
    );

    // 1 saat net limit (Mikrotik Session-Timeout)
    await pool.query(`DELETE FROM radreply WHERE username = $1 AND attribute = 'Session-Timeout'`, [username]);
    await pool.query(
      `INSERT INTO radreply (username, attribute, op, value)
       VALUES ($1, 'Session-Timeout', ':=', '3600')`,
      [username]
    );

    // Kullanıcı bilgilerini wifi_users tablosuna kaydet/güncelle
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

    return res.json({ ok: true, username, password });
  } catch (err) {
    console.error("otp/verify error:", err?.message || err, err?.response?.data || "");
    return res.status(500).json({ ok: false, error: "Sunucu hatası" });
  }
});

/** ---------- START ---------- **/
app.listen(PORT, "0.0.0.0", () => {
  console.log(`OTP API listening on port ${PORT}`);
});
