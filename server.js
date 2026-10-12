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
app.post("/api/connector/sms-receipt",async(req,res)=>{
  if(!safeEqual(req.get("X-SMS-Secret"),SMS_SECRET)) return res.status(401).json({error:"Unauthorized"});
  const {provider,trx_id,amount,source_verified,raw_sms_hash}=req.body||{};
  if(!["bkash","nagad","rocket"].includes(provider)||!clean(trx_id)||!Number.isFinite(Number(amount))||Number(amount)<=0||source_verified!==true||!clean(raw_sms_hash))
    return res.status(400).json({error:"Invalid receipt payload"});
  const client=await pool.connect();
  try{
    await client.query("BEGIN");
    const used=await client.query("SELECT id FROM payments WHERE LOWER(trx_id)=LOWER($1) FOR UPDATE",[clean(trx_id)]);
    if(!used.rowCount){await client.query("ROLLBACK");return res.status(404).json({error:"No matching submitted transaction"});}
    const p=await client.query("SELECT * FROM payments WHERE id=$1 FOR UPDATE",[used.rows[0].id]);
    if(p.rows[0].provider!==provider||Number(p.rows[0].amount)!==Number(amount)||p.rows[0].status!=="pending"){
      await client.query("ROLLBACK");return res.status(409).json({error:"Provider, amount or status mismatch; manual review required."});
    }
    const dup=await client.query("SELECT id FROM audit_logs WHERE action='sms_receipt_hash' AND details->>'hash'=$1",[clean(raw_sms_hash)]);
    if(dup.rowCount){await client.query("ROLLBACK");return res.status(409).json({error:"SMS receipt already processed"});}
    await client.query("UPDATE payments SET status='success',verification_source='sms',decided_at=NOW() WHERE id=$1",[p.rows[0].id]);
    await client.query("INSERT INTO audit_logs(action,payment_id,details) VALUES('sms_receipt_hash',$1,$2)",[p.rows[0].id,JSON.stringify({hash:raw_sms_hash,provider,amount})]);
    await client.query("INSERT INTO support_messages(payment_id,sender_role,body) VALUES($1,'system','Payment automatically verified from connector receipt.')",[p.rows[0].id]);
    await client.query("COMMIT");
    broadcast({type:"payment_update",paymentId:p.rows[0].id});
    res.json({ok:true,status:"success"});
  }catch(e){await client.query("ROLLBACK");res.status(500).json({error:"Receipt processing failed."});}
  finally{client.release();}
});
/* Privacy cleanup: remove transaction/support details after 12h from final decision.
   Keep no raw SMS, screenshots or message attachments in this starter. */
async function cleanup(){
  try{
    await pool.query("DELETE FROM payments WHERE status IN ('success','rejected') AND decided_at < NOW()-INTERVAL '12 hours'");
    await pool.query("DELETE FROM support_messages WHERE payment_id IS NULL AND created_at < NOW()-INTERVAL '12 hours'");
    await pool.query("DELETE FROM audit_logs WHERE created_at < NOW()-INTERVAL '30 days'");
  }catch(e){console.error("Cleanup failed:",e.message);}
}
setInterval(cleanup, 5*60*1000).unref();
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
wss.on("connection",(ws)=>{
  ws.send(JSON.stringify({type:"connected"}));
});
initDb().then(()=>server.listen(PORT,()=>console.log(`Sojib Pay listening on ${PORT}`))).catch(e=>{console.error("Startup failed",e);process.exit(1);});
