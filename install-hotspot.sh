#!/usr/bin/env bash
set -e

echo ">>> Updating system..."
sudo apt update -y

echo ">>> Installing packages (nginx, postgres, freeradius, nodejs)..."
sudo apt install -y nginx postgresql postgresql-contrib freeradius freeradius-postgresql nodejs npm git curl ufw

echo ">>> Configuring UFW..."
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 1812/udp
sudo ufw allow 1813/udp
echo "y" | sudo ufw enable || true

echo ">>> Creating PostgreSQL user & database..."
sudo -u postgres psql << 'EOF'
DO
$$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = 'wifi'
   ) THEN
      CREATE ROLE wifi LOGIN PASSWORD 'wifi_pass';
   END IF;
END
$$;

DO
$$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_database WHERE datname = 'wifidb'
   ) THEN
      CREATE DATABASE wifidb OWNER wifi;
   END IF;
END
$$;
EOF

echo ">>> Loading FreeRADIUS PostgreSQL schema..."
sudo -u postgres psql wifidb -f /etc/freeradius/3.0/mods-config/sql/main/postgresql/schema.sql

echo ">>> Creating OTP table..."
sudo -u postgres psql wifidb << 'EOF'
CREATE TABLE IF NOT EXISTS otp_requests(
 id SERIAL PRIMARY KEY,
 phone TEXT,
 otp_hash TEXT,
 expires_at TIMESTAMPTZ,
 used BOOLEAN DEFAULT false,
 created_at TIMESTAMPTZ DEFAULT now()
);
EOF

echo ">>> Configuring FreeRADIUS SQL module..."
sudo bash -c 'cat > /etc/freeradius/3.0/mods-available/sql' << 'EOF'
sql {
  driver = "rlm_sql_${dialect}"
  dialect = "postgresql"

  server = "127.0.0.1"
  port = 5432
  login = "wifi"
  password = "wifi_pass"

  radius_db = "wifidb"

  acct_table1 = "radacct"
  acct_table2 = "radacct"
  postauth_table = "radpostauth"

  authcheck_table = "radcheck"
  authreply_table = "radreply"

  deletestalesessions = yes

  sql_user_name = "%{User-Name}"

  connect_timeout = 3
  read_timeout = 3

  nas_table = "nas"
}
EOF

echo ">>> Enabling SQL module..."
sudo ln -sf /etc/freeradius/3.0/mods-available/sql /etc/freeradius/3.0/mods-enabled/sql

echo ">>> Adding MikroTik client (clients.conf)..."
sudo bash -c 'cat >> /etc/freeradius/3.0/clients.conf' << 'EOF'

client mikrotik-hotspot {
    ipaddr = 1.2.3.4
    secret = SuperSecretSharedKey
    nas_type = other
}
EOF

echo ">>> Restarting FreeRADIUS..."
sudo systemctl restart freeradius

echo ">>> Installing OTP Node.js service..."
sudo mkdir -p /opt/wifi-otp
sudo bash -c 'cat > /opt/wifi-otp/index.js' << 'EOF'
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');
const { Client } = require('pg');

const app = express();
app.use(bodyParser.json());

const pgc = new Client({
  connectionString: "postgres://wifi:wifi_pass@127.0.0.1:5432/wifidb"
});
pgc.connect();

function genOtp() {
  return (Math.floor(100000 + Math.random() * 900000)).toString();
}

// OTP gönder
app.post('/request-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.json({ ok:false, msg:"phone required" });

    const otp = genOtp();
    const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
    const expires = new Date(Date.now() + 5 * 60 * 1000);

    await pgc.query(
      "INSERT INTO otp_requests(phone, otp_hash, expires_at) VALUES($1,$2,$3)",
      [phone, otpHash, expires]
    );

    // TODO: SMS entegrasyonu
    // Örnek NetGSM:
    // await axios.get(`https://api.netgsm.com.tr/sms/send/get/?usercode=KULLANICI&password=SIFRE&gsmno=${phone}&message=Kodunuz:${otp}`);

    console.log("OTP (dev):", phone, otp);
    res.json({ ok:true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, msg:"server error" });
  }
});

// OTP doğrula + RADIUS user oluştur
app.post('/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) return res.json({ ok:false, msg:"missing fields" });

    const hash = crypto.createHash('sha256').update(otp).digest('hex');

    const r = await pgc.query(
      "SELECT * FROM otp_requests WHERE phone=$1 AND otp_hash=$2 AND used=false AND expires_at>now() ORDER BY id DESC LIMIT 1",
      [phone, hash]
    );

    if (!r.rows.length) return res.json({ ok:false, msg:"invalid or expired" });

    await pgc.query("UPDATE otp_requests SET used=true WHERE id=$1", [r.rows[0].id]);

    const password = crypto.randomBytes(4).toString("hex");

    await pgc.query("DELETE FROM radcheck WHERE username=$1", [phone]);
    await pgc.query("DELETE FROM radreply WHERE username=$1", [phone]);

    await pgc.query(
      "INSERT INTO radcheck (username, attribute, op, value) VALUES ($1,'Cleartext-Password',':=',$2)",
      [phone, password]
    );

    await pgc.query(
      "INSERT INTO radreply (username, attribute, op, value) VALUES ($1,'Session-Timeout',':=','3600')",
      [phone]
    );

    res.json({ ok:true, username: phone, password });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, msg:"server error" });
  }
});

app.listen(3000, () => console.log("OTP server running on :3000"));
EOF

echo ">>> Installing Node.js deps..."
cd /opt/wifi-otp
npm init -y >/dev/null 2>&1 || true
npm install express body-parser pg axios crypto >/dev/null 2>&1

echo ">>> Creating systemd service for wifi-otp..."
sudo bash -c 'cat > /etc/systemd/system/wifi-otp.service' << 'EOF'
[Unit]
Description=WiFi OTP Service
After=network.target postgresql.service

[Service]
ExecStart=/usr/bin/node /opt/wifi-otp/index.js
Restart=always
User=root
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable wifi-otp
sudo systemctl start wifi-otp

echo ">>> DONE."
echo "1) /etc/freeradius/3.0/clients.conf içindeki 1.2.3.4 yerine MikroTik'in WAN IP'sini yaz."
echo "2) secret = SuperSecretSharedKey kısmını hem burada hem Mikrotik Radius ayarında aynı yap."
echo "3) /opt/wifi-otp/index.js içindeki TODO kısmına NetGSM veya AWS SNS SMS kodunu ekle."

