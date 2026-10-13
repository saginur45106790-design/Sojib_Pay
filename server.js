require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const SMS_SECRET = process.env.SMS_WEBHOOK_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be set to a random secret at least 32 characters long.");
  process.exit(1);
}
if (!SMS_SECRET || SMS_SECRET.length < 24) {
  console.error("SMS_WEBHOOK_SECRET must be set to a random secret at least 24 characters long.");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required. Use PostgreSQL; Render's filesystem is not persistent.");
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : undefined
});
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use("/api/", rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false }));

const money = n => Number(n).toFixed(2);
const clean = v => String(v ?? "").trim();
const safeEqual = (a,b) => {
  const crypto = require("crypto");
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer', blocked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payment_settings (
      provider TEXT PRIMARY KEY CHECK (provider IN ('bkash','nagad','rocket')),
      account_number TEXT NOT NULL DEFAULT '', enabled BOOLEAN NOT NULL DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0), provider TEXT NOT NULL,
      trx_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','success','rejected','support_review')),
      verification_source TEXT NOT NULL DEFAULT 'manual',
      rejection_reason TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      decided_at TIMESTAMPTZ, expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '12 hours')
    );
    CREATE UNIQUE INDEX IF NOT EXISTS payments_trx_id_unique ON payments (LOWER(trx_id));
    CREATE TABLE IF NOT EXISTS support_messages (
      id BIGSERIAL PRIMARY KEY, payment_id BIGINT REFERENCES payments(id) ON DELETE CASCADE,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL, sender_role TEXT NOT NULL
        CHECK (sender_role IN ('customer','admin','system')), body TEXT NOT NULL,
      attachment_name TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY, admin_id BIGINT, action TEXT NOT NULL, payment_id BIGINT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS merchants (
      id BIGSERIAL PRIMARY KEY, user_id BIGINT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      business_name TEXT NOT NULL, website TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending_review'
        CHECK (status IN ('pending_review','approved','suspended')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS merchant_api_keys (
      id BIGSERIAL PRIMARY KEY, merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, secret_hash TEXT NOT NULL,
      label TEXT NOT NULL DEFAULT 'Default key', revoked BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payment_requests (
      id BIGSERIAL PRIMARY KEY, merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
      public_id TEXT UNIQUE NOT NULL, amount NUMERIC(12,2) NOT NULL CHECK(amount > 0), currency TEXT NOT NULL DEFAULT 'BDT',
      description TEXT NOT NULL DEFAULT '', customer_reference TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 minutes')
    );
    CREATE TABLE IF NOT EXISTS sms_receipts (
      id BIGSERIAL PRIMARY KEY, provider TEXT NOT NULL, trx_id TEXT NOT NULL, amount NUMERIC(12,2) NOT NULL,
      raw_sms_hash TEXT NOT NULL UNIQUE, sender_metadata TEXT NOT NULL DEFAULT '', balance_before NUMERIC(14,2),
      balance_after NUMERIC(14,2), review_status TEXT NOT NULL DEFAULT 'pending_review', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO payment_settings(provider, account_number) VALUES
      ('bkash',''),('nagad',''),('rocket','') ON CONFLICT(provider) DO NOTHING;
  `);
  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const email = process.env.ADMIN_EMAIL.toLowerCase().trim();
    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (!exists.rowCount) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await pool.query("INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin')", [email, hash]);
      console.log("Initial admin created:", email);
    } else {
      console.log("Existing admin preserved. Change password through secure account management before public launch.");
    }
  }
}
function auth(req,res,next) {
  const token = req.cookies.sp_token || (req.headers.authorization || "").replace(/^Bearer /i,"");
  try {
    if (!token) throw new Error("missing");
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({error:"Please sign in."}); }
}
function admin(req,res,next) {
  if (req.user?.role !== "admin") return res.status(403).json({error:"Admin access required."});
  next();
}
function issueToken(user,res) {
  const token = jwt.sign({id:user.id,email:user.email,role:user.role}, JWT_SECRET, {expiresIn:"12h"});
  res.cookie("sp_token", token, {httpOnly:true, secure:process.env.NODE_ENV==="production", sameSite:"strict", maxAge:12*60*60*1000});
}
function broadcast(obj) {
  const data = JSON.stringify(obj);
  for (const ws of wss.clients) if (ws.readyState === 1) ws.send(data);
}
app.get("/api/health", (_req,res)=>res.json({ok:true,service:"Sojib Pay"}));
app.post("/api/auth/signup", rateLimit({windowMs:60*60*1000,limit:10}), async (req,res)=>{
  try {
    const email=clean(req.body.email).toLowerCase(), password=String(req.body.password||"");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10)
      return res.status(400).json({error:"Enter a valid email and password of at least 10 characters."});
    const hash=await bcrypt.hash(password,12);
    const r=await pool.query("INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email,role", [email,hash]);
    issueToken(r.rows[0],res); res.json({user:r.rows[0]});
  } catch(e) { res.status(e.code==="23505"?409:500).json({error:e.code==="23505"?"Email already registered.":"Could not create account."}); }
});
app.post("/api/auth/login", rateLimit({windowMs:15*60*1000,limit:12}), async (req,res)=>{
  const email=clean(req.body.email).toLowerCase(), password=String(req.body.password||"");
  const r=await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  const u=r.rows[0];
  if (!u || u.blocked || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:"Invalid credentials or account unavailable."});
  issueToken(u,res); res.json({user:{id:u.id,email:u.email,role:u.role}});
});
app.post("/api/auth/logout", (_req,res)=>{res.clearCookie("sp_token",{httpOnly:true,sameSite:"strict",secure:process.env.NODE_ENV==="production"});res.json({ok:true});});
app.get("/api/me",auth,(req,res)=>res.json({user:req.user}));

app.get("/api/payment-settings",async(_req,res)=>{
  const r=await pool.query("SELECT provider,account_number,enabled FROM payment_settings ORDER BY provider");
  res.json({providers:r.rows.map(x=>({...x,account_number:x.enabled?x.account_number:""}))});
});
app.post("/api/payments",auth,async(req,res)=>{
  const amount=Number(req.body.amount), provider=clean(req.body.provider).toLowerCase(), trx=clean(req.body.trx_id);
  if (!Number.isFinite(amount)||amount<1||amount>1000000||!["bkash","nagad","rocket"].includes(provider)||trx.length<5||trx.length>80)
    return res.status(400).json({error:"Enter a valid amount, provider and transaction ID."});
  const setting=await pool.query("SELECT enabled FROM payment_settings WHERE provider=$1",[provider]);
  if (!setting.rows[0]?.enabled) return res.status(400).json({error:"This payment method is temporarily unavailable."});
  try {
    const r=await pool.query("INSERT INTO payments(user_id,amount,provider,trx_id) VALUES($1,$2,$3,$4) RETURNING id,amount,provider,trx_id,status,created_at,expires_at",
      [req.user.id,amount,provider,trx]);
    await pool.query("INSERT INTO support_messages(payment_id,user_id,sender_role,body) VALUES($1,$2,'system',$3)",[r.rows[0].id,req.user.id,"Payment submitted. Verification may take up to 5 minutes."]);
    broadcast({type:"payment_update",paymentId:r.rows[0].id});
    res.status(201).json({payment:r.rows[0]});
  } catch(e) {
    if(e.code==="23505") return res.status(409).json({error:"This transaction ID has already been submitted. Contact support if you believe this is an error."});
    res.status(500).json({error:"Could not submit payment."});
  }
});
app.get("/api/payments/mine",auth,async(req,res)=>{
  const r=await pool.query("SELECT id,amount,provider,trx_id,status,rejection_reason,created_at,decided_at,expires_at FROM payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100",[req.user.id]);
  res.json({payments:r.rows});
});
app.get("/api/payments/:id",auth,async(req,res)=>{
  const r=await pool.query("SELECT id,user_id,amount,provider,trx_id,status,rejection_reason,created_at,decided_at,expires_at FROM payments WHERE id=$1",[req.params.id]);
  if(!r.rowCount) return res.status(404).json({error:"Not found"});
  if(req.user.role!=="admin" && String(r.rows[0].user_id)!==String(req.user.id)) return res.status(403).json({error:"Forbidden"});
  res.json({payment:r.rows[0]});
});
app.get("/api/support/:paymentId",auth,async(req,res)=>{
  const p=await pool.query("SELECT id,user_id,status,expires_at FROM payments WHERE id=$1",[req.params.paymentId]);
  if(!p.rowCount) return res.status(404).json({error:"Payment not found"});
  if(req.user.role!=="admin" && String(p.rows[0].user_id)!==String(req.user.id)) return res.status(403).json({error:"Forbidden"});
  const r=await pool.query("SELECT id,sender_role,body,attachment_name,created_at FROM support_messages WHERE payment_id=$1 ORDER BY created_at ASC",[req.params.paymentId]);
  res.json({messages:r.rows, payment:p.rows[0]});
});
app.post("/api/support/:paymentId",auth,async(req,res)=>{
  const body=clean(req.body.body);
  if(!body||body.length>3000) return res.status(400).json({error:"Message must be 1–3000 characters."});
  const p=await pool.query("SELECT id,user_id,status,expires_at FROM payments WHERE id=$1",[req.params.paymentId]);
  if(!p.rowCount) return res.status(404).json({error:"Payment not found"});
  const pay=p.rows[0];
  if(req.user.role!=="admin" && String(pay.user_id)!==String(req.user.id)) return res.status(403).json({error:"Forbidden"});
  if(req.user.role!=="admin" && pay.status==="rejected") return res.status(403).json({error:"This support case is closed. Contact the site owner through the published contact channel if you believe this is incorrect."});
  const r=await pool.query("INSERT INTO support_messages(payment_id,user_id,sender_role,body) VALUES($1,$2,$3,$4) RETURNING id,sender_role,body,created_at",
    [pay.id,req.user.id,req.user.role==="admin"?"admin":"customer",body]);
  broadcast({type:"support_message",paymentId:pay.id});
  res.status(201).json({message:r.rows[0]});
});
app.get("/api/admin/overview",auth,admin,async(_req,res)=>{
  const stats=await pool.query(`SELECT
    COUNT(*) FILTER(WHERE status='pending')::int AS pending_count,
    COUNT(*) FILTER(WHERE status='success')::int AS success_count,
    COUNT(*) FILTER(WHERE status='rejected')::int AS rejected_count,
    COALESCE(SUM(amount) FILTER(WHERE status='success'),0)::text AS approved_amount,
    COALESCE(SUM(amount) FILTER(WHERE status='rejected'),0)::text AS rejected_amount,
    COALESCE(SUM(amount) FILTER(WHERE status IN ('pending','support_review')),0)::text AS pending_amount
    FROM payments`);
  const cases=await pool.query("SELECT COUNT(DISTINCT payment_id)::int AS count FROM support_messages WHERE sender_role='customer' AND created_at > NOW()-INTERVAL '24 hours'");
  res.json({stats:stats.rows[0],support_cases:cases.rows[0].count});
});
app.get("/api/admin/payments",auth,admin,async(req,res)=>{
  const status=clean(req.query.status);
  const params=[]; let sql=`SELECT p.*,u.email FROM payments p LEFT JOIN users u ON u.id=p.user_id`;
  if(["pending","success","rejected","support_review"].includes(status)){params.push(status);sql+=" WHERE p.status=$1";}
  sql+=" ORDER BY p.created_at DESC LIMIT 300";
  const r=await pool.query(sql,params);res.json({payments:r.rows});
});
app.post("/api/admin/payments/:id/decision",auth,admin,async(req,res)=>{
  const decision=clean(req.body.decision), reason=clean(req.body.reason);
  if(!["success","rejected","support_review"].includes(decision)) return res.status(400).json({error:"Invalid decision"});
  if(decision==="rejected" && reason.length<3) return res.status(400).json({error:"A rejection reason is required."});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const p=await client.query("SELECT * FROM payments WHERE id=$1 FOR UPDATE",[req.params.id]);
    if(!p.rowCount) {await client.query("ROLLBACK");return res.status(404).json({error:"Payment not found"});}
    if(p.rows[0].status==="success" && decision!=="success"){await client.query("ROLLBACK");return res.status(409).json({error:"A successful payment cannot be reversed here."});}
    const updated=await client.query("UPDATE payments SET status=$1,rejection_reason=$2,decided_at=NOW() WHERE id=$3 RETURNING *",[decision,decision==="rejected"?reason:null,req.params.id]);
    await client.query("INSERT INTO audit_logs(admin_id,action,payment_id,details) VALUES($1,$2,$3,$4)",[req.user.id,"payment_decision",req.params.id,JSON.stringify({decision,reason})]);
    await client.query("INSERT INTO support_messages(payment_id,sender_role,body) VALUES($1,'system',$2)",[req.params.id,decision==="success"?"Payment approved by support.":decision==="rejected"?"Payment rejected: "+reason:"Payment moved to support review."]);
    await client.query("COMMIT");
    broadcast({type:"payment_update",paymentId:Number(req.params.id)});
    res.json({payment:updated.rows[0]});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"Could not update payment."});}
  finally{client.release();}
});
app.put("/api/admin/settings/:provider",auth,admin,async(req,res)=>{
  const provider=clean(req.params.provider).toLowerCase(), number=clean(req.body.account_number), enabled=Boolean(req.body.enabled);
  if(!["bkash","nagad","rocket"].includes(provider)||number.length>40) return res.status(400).json({error:"Invalid provider or number"});
  await pool.query("UPDATE payment_settings SET account_number=$1,enabled=$2 WHERE provider=$3",[number,enabled,provider]);
  await pool.query("INSERT INTO audit_logs(admin_id,action,details) VALUES($1,'payment_settings_update',$2)",[req.user.id,JSON.stringify({provider,enabled})]);
  res.json({ok:true});
});
app.get("/api/admin/settings",auth,admin,async(_req,res)=>{
  const r=await pool.query("SELECT provider,account_number,enabled FROM payment_settings ORDER BY provider");res.json({settings:r.rows});
});
/*
 * SMS connector contract. This endpoint does NOT read SMS from a phone.
 * A separately audited Android collector must send parsed incoming transaction data
 * over HTTPS with X-SMS-Secret. Never trust a sender label alone.
 * Only accept provider-originated receipt messages that the collector has classified
 * and include raw SMS hash, sender metadata and amount/trx_id.
 */
// Merchant onboarding and API credentials. New merchants are NOT approved automatically.
const crypto = require("crypto");
const hashSecret = value => crypto.createHash("sha256").update(String(value)).digest("hex");
app.post("/api/merchant/apply",auth,async(req,res)=>{
  const business=clean(req.body.business_name), website=clean(req.body.website);
  if(business.length<2||business.length>120||website.length>300) return res.status(400).json({error:"Enter a valid business name and website."});
  try {
    const r=await pool.query("INSERT INTO merchants(user_id,business_name,website) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET business_name=EXCLUDED.business_name,website=EXCLUDED.website RETURNING id,business_name,website,status,created_at",[req.user.id,business,website]);
    res.status(201).json({merchant:r.rows[0]});
  } catch(e){res.status(500).json({error:"Could not submit merchant application."});}
});
app.get("/api/merchant/me",auth,async(req,res)=>{
  const r=await pool.query("SELECT id,business_name,website,status,created_at FROM merchants WHERE user_id=$1",[req.user.id]);
  if(!r.rowCount) return res.json({merchant:null});
  const m=r.rows[0];
  const stats=await pool.query("SELECT COUNT(*)::int AS requests,COUNT(*) FILTER(WHERE status='success')::int AS successful,COALESCE(SUM(amount) FILTER(WHERE status='success'),0)::text AS total FROM payment_requests WHERE merchant_id=$1",[m.id]);
  const keys=await pool.query("SELECT id,key_prefix,label,revoked,created_at FROM merchant_api_keys WHERE merchant_id=$1 ORDER BY id DESC",[m.id]);
  const requests=await pool.query("SELECT public_id,amount,currency,description,status,created_at,expires_at FROM payment_requests WHERE merchant_id=$1 ORDER BY created_at DESC LIMIT 50",[m.id]);
  res.json({merchant:m,stats:stats.rows[0],keys:keys.rows,requests:requests.rows});
});
app.post("/api/merchant/keys",auth,async(req,res)=>{
  const m=await pool.query("SELECT id,status FROM merchants WHERE user_id=$1",[req.user.id]);
  if(!m.rowCount) return res.status(400).json({error:"Apply for a merchant account first."});
  if(m.rows[0].status!=="approved") return res.status(403).json({error:"Merchant must be approved before creating live API keys."});
  const apiKey="sp_live_"+crypto.randomBytes(18).toString("hex"), secret="sps_"+crypto.randomBytes(32).toString("hex");
  await pool.query("INSERT INTO merchant_api_keys(merchant_id,key_prefix,key_hash,secret_hash,label) VALUES($1,$2,$3,$4,$5)",[m.rows[0].id,apiKey.slice(0,14),hashSecret(apiKey),hashSecret(secret),clean(req.body.label).slice(0,60)||"Default key"]);
  res.status(201).json({warning:"Copy these credentials now. The secret is shown only once. Do not put it in browser code.",api_key:apiKey,api_secret:secret});
});
app.post("/api/merchant/keys/:id/revoke",auth,async(req,res)=>{
  const r=await pool.query("UPDATE merchant_api_keys k SET revoked=TRUE FROM merchants m WHERE k.merchant_id=m.id AND m.user_id=$1 AND k.id=$2 RETURNING k.id",[req.user.id,req.params.id]);
  if(!r.rowCount)return res.status(404).json({error:"Key not found"});res.json({ok:true});
});
async function merchantApiAuth(req,res,next){
  const key=clean(req.get("X-SojibPay-Key"));
  if(!key.startsWith("sp_live_"))return res.status(401).json({error:"Merchant API key required."});
  const r=await pool.query("SELECT k.id AS key_id,m.id AS merchant_id,m.status FROM merchant_api_keys k JOIN merchants m ON m.id=k.merchant_id WHERE k.key_hash=$1 AND k.revoked=FALSE",[hashSecret(key)]);
  if(!r.rowCount||r.rows[0].status!=="approved")return res.status(403).json({error:"Merchant account or API key is not active."});
  req.merchant=r.rows[0];next();
}
app.post("/api/v1/payment-requests",merchantApiAuth,async(req,res)=>{
  const amount=Number(req.body.amount),description=clean(req.body.description),reference=clean(req.body.reference);
  if(!Number.isFinite(amount)||amount<1||amount>1000000||description.length>250||reference.length>100)return res.status(400).json({error:"Invalid amount, description or reference."});
  const publicId="spay_"+crypto.randomBytes(16).toString("hex");
  const r=await pool.query("INSERT INTO payment_requests(merchant_id,public_id,amount,description,customer_reference) VALUES($1,$2,$3,$4,$5) RETURNING public_id,amount,currency,description,status,created_at,expires_at",[req.merchant.merchant_id,publicId,amount,description,reference]);
  res.status(201).json({payment:r.rows[0],checkout_url:`${req.protocol}://${req.get("host")}/checkout.html?id=${publicId}`,note:"Checkout requests are records only until an approved payment provider is integrated."});
});
app.post("/api/merchant/requests",auth,async(req,res)=>{
  const m=await pool.query("SELECT id,status FROM merchants WHERE user_id=$1",[req.user.id]);
  if(!m.rowCount)return res.status(400).json({error:"Apply for a merchant account first."});
  if(m.rows[0].status!=="approved")return res.status(403).json({error:"Merchant account must be approved before creating live payment requests."});
  const amount=Number(req.body.amount),description=clean(req.body.description),reference=clean(req.body.reference);
  if(!Number.isFinite(amount)||amount<1||amount>1000000||description.length>250||reference.length>100)return res.status(400).json({error:"Invalid amount, description or reference."});
  const publicId="spay_"+crypto.randomBytes(16).toString("hex");
  const r=await pool.query("INSERT INTO payment_requests(merchant_id,public_id,amount,description,customer_reference) VALUES($1,$2,$3,$4,$5) RETURNING public_id,amount,currency,description,status,created_at,expires_at",[m.rows[0].id,publicId,amount,description,reference]);
  res.status(201).json({payment:r.rows[0],checkout_url:`${req.protocol}://${req.get("host")}/checkout.html?id=${publicId}`,note:"This is a request record, not a live provider checkout."});
});
app.get("/api/checkout/:publicId",async(req,res)=>{
  const r=await pool.query("SELECT p.public_id,p.amount,p.currency,p.description,p.status,p.expires_at,m.business_name FROM payment_requests p JOIN merchants m ON m.id=p.merchant_id WHERE p.public_id=$1",[req.params.publicId]);
  if(!r.rowCount)return res.status(404).json({error:"Payment request not found."});res.json({payment:r.rows[0]});
});
app.get("/api/admin/sms-receipts",auth,admin,async(_req,res)=>{
  const r=await pool.query("SELECT id,provider,trx_id,amount,sender_metadata,balance_before,balance_after,review_status,created_at FROM sms_receipts ORDER BY created_at DESC LIMIT 300");res.json({receipts:r.rows});
});
app.get("/api/admin/merchants",auth,admin,async(_req,res)=>{
  const r=await pool.query("SELECT m.*,u.email FROM merchants m JOIN users u ON u.id=m.user_id ORDER BY m.created_at DESC LIMIT 300");res.json({merchants:r.rows});
});
app.post("/api/admin/merchants/:id/status",auth,admin,async(req,res)=>{
  const status=clean(req.body.status);if(!["pending_review","approved","suspended"].includes(status))return res.status(400).json({error:"Invalid merchant status."});
  const r=await pool.query("UPDATE merchants SET status=$1 WHERE id=$2 RETURNING id,status,business_name",[status,req.params.id]);
  if(!r.rowCount)return res.status(404).json({error:"Merchant not found."});
  await pool.query("INSERT INTO audit_logs(admin_id,action,details) VALUES($1,'merchant_status_update',$2)",[req.user.id,JSON.stringify({merchant_id:req.params.id,status})]);res.json({merchant:r.rows[0]});
});

app.post("/api/connector/sms-receipt",async(req,res)=>{
  if(!safeEqual(req.get("X-SMS-Secret"),SMS_SECRET)) return res.status(401).json({error:"Unauthorized"});
  const {provider,trx_id,amount,raw_sms_hash,sender_metadata,balance_before,balance_after}=req.body||{};
  if(!["bkash","nagad","rocket"].includes(provider)||!clean(trx_id)||!Number.isFinite(Number(amount))||Number(amount)<=0||!/^([a-f0-9]{64})$/i.test(clean(raw_sms_hash))||clean(sender_metadata).length>200)
    return res.status(400).json({error:"Invalid receipt payload"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const dup=await client.query("SELECT id FROM sms_receipts WHERE raw_sms_hash=$1",[clean(raw_sms_hash)]);
    if(dup.rowCount){await client.query("ROLLBACK");return res.status(409).json({error:"SMS receipt already received"});}
    const rec=await client.query("INSERT INTO sms_receipts(provider,trx_id,amount,raw_sms_hash,sender_metadata,balance_before,balance_after,review_status) VALUES($1,$2,$3,$4,$5,$6,$7,'pending_review') RETURNING id",[provider,clean(trx_id),amount,clean(raw_sms_hash),clean(sender_metadata),Number.isFinite(Number(balance_before))?Number(balance_before):null,Number.isFinite(Number(balance_after))?Number(balance_after):null]);
    const used=await client.query("SELECT * FROM payments WHERE LOWER(trx_id)=LOWER($1) FOR UPDATE",[clean(trx_id)]);
    if(used.rowCount){
      const p=used.rows[0];
      await client.query("UPDATE payments SET status='support_review',verification_source='sms_review' WHERE id=$1 AND status='pending'",[p.id]);
      await client.query("INSERT INTO audit_logs(action,payment_id,details) VALUES('sms_receipt_review',$1,$2)",[p.id,JSON.stringify({receipt_id:rec.rows[0].id,provider_match:p.provider===provider,amount_match:Number(p.amount)===Number(amount),hash:raw_sms_hash})]);
      await client.query("INSERT INTO support_messages(payment_id,sender_role,body) VALUES($1,'system','SMS receipt received. It is awaiting manual verification; it has not been auto-approved.')",[p.id]);
    }
    await client.query("COMMIT");
    res.status(202).json({ok:true,status:"pending_review",receipt_id:rec.rows[0].id,note:"SMS receipt is queued for review and never auto-approves a payment."});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"Receipt processing failed."});}
  finally{client.release();}
});
/* Retain payment records for reconciliation and duplicate prevention. Set retention policy with legal/accounting advice. */
async function cleanup(){
  try { await pool.query("DELETE FROM audit_logs WHERE created_at < NOW()-INTERVAL '180 days'"); }
  catch(e){ console.error("Cleanup failed:",e.message); }
}
setInterval(cleanup, 24*60*60*1000).unref();
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
wss.on("connection",(ws)=>{
  ws.send(JSON.stringify({type:"connected"}));
});
initDb().then(()=>server.listen(PORT,()=>console.log(`Sojib Pay listening on ${PORT}`))).catch(e=>{console.error("Startup failed",e);process.exit(1);});
