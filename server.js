const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "pos-data");
const DATA_FILE = path.join(DATA_DIR, "store-data.json");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const AUDIT_FILE = path.join(DATA_DIR, "audit.log");
const BACKUP_DIR = path.join(DATA_DIR, "backups");
const PORT = Number(process.env.PORT || 8080);
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_SECRET_BEFORE_LIVE";
const COOKIE_NAME = "pos_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const sessions = new Map();

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".css": "text/css; charset=utf-8",
  ".txt": "text/plain; charset=utf-8"
};

function ensureDirs() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

function defaultAccounts() {
  return [
    { code: "1000", name: "Cash on Hand", type: "Asset" },
    { code: "1010", name: "Cash in Bank", type: "Asset" },
    { code: "1100", name: "Accounts Receivable", type: "Asset" },
    { code: "1200", name: "Merchandise Inventory", type: "Asset" },
    { code: "1210", name: "Expired / Spoiled Inventory", type: "Asset" },
    { code: "1300", name: "Store Supplies", type: "Asset" },
    { code: "1500", name: "Store Equipment", type: "Asset" },
    { code: "1510", name: "Accumulated Depreciation - Equipment", type: "Contra Asset" },
    { code: "1600", name: "Building", type: "Asset" },
    { code: "1610", name: "Accumulated Depreciation - Building", type: "Contra Asset" },
    { code: "1700", name: "Leasehold Improvements", type: "Asset" },
    { code: "1710", name: "Accumulated Depreciation - Leasehold Improvements", type: "Contra Asset" },
    { code: "2000", name: "Accounts Payable", type: "Liability" },
    { code: "2100", name: "Loans Payable", type: "Liability" },
    { code: "2200", name: "Taxes Payable", type: "Liability" },
    { code: "2300", name: "Accrued Expenses", type: "Liability" },
    { code: "3000", name: "Owner Capital", type: "Equity" },
    { code: "3100", name: "Owner Drawings", type: "Equity" },
    { code: "4000", name: "Sales Revenue", type: "Revenue" },
    { code: "4100", name: "Sales Returns and Allowances", type: "Contra Revenue" },
    { code: "4200", name: "Interest Income", type: "Other Income" },
    { code: "4300", name: "Other Income", type: "Other Income" },
    { code: "5000", name: "Cost of Goods Sold", type: "Expense" },
    { code: "5100", name: "Inventory Shrinkage", type: "Expense" },
    { code: "5110", name: "Expired / Spoiled Goods Expense", type: "Expense" },
    { code: "5200", name: "Rent Expense", type: "Expense" },
    { code: "5300", name: "Utilities Expense", type: "Expense" },
    { code: "5400", name: "Supplies Expense", type: "Expense" },
    { code: "5500", name: "Cash Short / Over", type: "Expense" },
    { code: "5600", name: "Depreciation Expense - Equipment", type: "Expense" },
    { code: "5610", name: "Depreciation Expense - Building", type: "Expense" },
    { code: "5700", name: "Repairs and Maintenance", type: "Expense" },
    { code: "5800", name: "Delivery / Freight Expense", type: "Expense" },
    { code: "5900", name: "Bank Charges", type: "Expense" }
  ];
}

function defaultState() {
  return {
    products: [
      { id: "prd-coffee", sku: "COF-001", name: "House Coffee", category: "Drinks", price: 75, cost: 35, stock: 42, reorder: 10 },
      { id: "prd-bread", sku: "BRD-002", name: "Cheese Bread", category: "Bakery", price: 38, cost: 18, stock: 28, reorder: 8 },
      { id: "prd-milk", sku: "MLK-003", name: "Fresh Milk 1L", category: "Grocery", price: 112, cost: 86, stock: 9, reorder: 10 },
      { id: "prd-rice", sku: "RCE-004", name: "Rice 5kg", category: "Grocery", price: 310, cost: 260, stock: 16, reorder: 5 }
    ],
    sales: [],
    stockLedger: [],
    receivables: [],
    receivableLedger: [],
    drawers: [],
    activeDrawerId: null,
    cashier: "Owner",
    accounts: defaultAccounts(),
    journalEntries: [],
    accountingMigrated: true
  };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 32, "sha256").toString("hex");
  return { salt, hash };
}

function verifyPassword(password, user) {
  const candidate = hashPassword(password, user.salt).hash;
  return crypto.timingSafeEqual(Buffer.from(candidate, "hex"), Buffer.from(user.hash, "hex"));
}

function initFiles() {
  ensureDirs();
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(defaultState(), null, 2));
  }
  if (!fs.existsSync(USERS_FILE)) {
    const password = process.env.POS_ADMIN_PASSWORD || "ChangeMe123!";
    const credentials = hashPassword(password);
    const users = [{
      id: crypto.randomUUID(),
      username: "admin",
      role: "admin",
      salt: credentials.salt,
      hash: credentials.hash,
      createdAt: new Date().toISOString()
    }];
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log("Default admin created: username admin");
    if (!process.env.POS_ADMIN_PASSWORD) console.log("Default password: ChangeMe123!  Change this before live use.");
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeJsonAtomic(file, value) {
  const temp = `${file}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(value, null, 2));
  fs.renameSync(temp, file);
}

function backupData() {
  if (!fs.existsSync(DATA_FILE)) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  fs.copyFileSync(DATA_FILE, path.join(BACKUP_DIR, `store-data-${stamp}.json`));
}

function audit(req, user, action, details = {}) {
  const row = {
    at: new Date().toISOString(),
    ip: req.socket.remoteAddress,
    user: user ? user.username : null,
    role: user ? user.role : null,
    action,
    details
  };
  fs.appendFileSync(AUDIT_FILE, `${JSON.stringify(row)}\n`);
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function makeCookie(sessionId) {
  const signed = `${sessionId}.${sign(sessionId)}`;
  const parts = [
    `${COOKIE_NAME}=${signed}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
  ];
  if (process.env.NODE_ENV === "production") parts.push("Secure");
  return parts.join("; ");
}

function clearCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").filter(Boolean).map(cookie => {
    const [key, ...rest] = cookie.trim().split("=");
    return [key, rest.join("=")];
  }));
}

function currentUser(req) {
  const raw = parseCookies(req)[COOKIE_NAME];
  if (!raw) return null;
  const [sessionId, digest] = raw.split(".");
  if (!sessionId || digest !== sign(sessionId)) return null;
  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_TTL_MS;
  return session.user;
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 10 * 1024 * 1024) reject(new Error("Request body too large"));
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(error);
      }
    });
  });
}

function serveStatic(req, res) {
  const url = new URL(req.url, "http://localhost");
  const cleanPath = url.pathname === "/" ? "/pos-system.html" : url.pathname;
  const fullPath = path.normalize(path.join(ROOT, cleanPath));
  if (!fullPath.startsWith(ROOT)) return send(res, 403, "Forbidden");
  if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) return send(res, 404, "Not found");
  const ext = path.extname(fullPath);
  res.writeHead(200, {
    "Content-Type": MIME[ext] || "application/octet-stream",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()"
  });
  fs.createReadStream(fullPath).pipe(res);
}

async function handleApi(req, res) {
  const user = currentUser(req);
  const url = new URL(req.url, "http://localhost");

  if (url.pathname === "/api/health") return send(res, 200, { ok: true });

  if (url.pathname === "/api/login" && req.method === "POST") {
    const body = await readBody(req);
    const users = readJson(USERS_FILE);
    const found = users.find(item => item.username === body.username);
    if (!found || !verifyPassword(String(body.password || ""), found)) {
      audit(req, null, "login_failed", { username: body.username });
      return send(res, 401, { error: "Invalid username or password" });
    }
    const sessionId = crypto.randomUUID();
    const safeUser = { id: found.id, username: found.username, role: found.role };
    sessions.set(sessionId, { user: safeUser, expiresAt: Date.now() + SESSION_TTL_MS });
    audit(req, safeUser, "login");
    return send(res, 200, { user: safeUser }, { "Set-Cookie": makeCookie(sessionId) });
  }

  if (url.pathname === "/api/logout" && req.method === "POST") {
    audit(req, user, "logout");
    return send(res, 200, { ok: true }, { "Set-Cookie": clearCookie() });
  }

  if (!user) return send(res, 401, { error: "Authentication required" });

  if (url.pathname === "/api/me") return send(res, 200, { user });

  if (url.pathname === "/api/state" && req.method === "GET") {
    return send(res, 200, readJson(DATA_FILE));
  }

  if (url.pathname === "/api/state" && req.method === "PUT") {
    if (!["admin", "manager", "cashier"].includes(user.role)) return send(res, 403, { error: "Forbidden" });
    const body = await readBody(req);
    if (!body || typeof body !== "object" || !Array.isArray(body.products) || !Array.isArray(body.accounts)) {
      return send(res, 400, { error: "Invalid POS data" });
    }
    backupData();
    writeJsonAtomic(DATA_FILE, body);
    audit(req, user, "state_saved", {
      products: body.products.length,
      sales: Array.isArray(body.sales) ? body.sales.length : 0,
      journalEntries: Array.isArray(body.journalEntries) ? body.journalEntries.length : 0
    });
    return send(res, 200, { ok: true });
  }

  if (url.pathname === "/api/backup" && req.method === "POST") {
    if (user.role !== "admin") return send(res, 403, { error: "Forbidden" });
    backupData();
    audit(req, user, "backup_created");
    return send(res, 200, { ok: true });
  }
if (url.pathname === "/api/create-cashier" && req.method === "GET") {

  const users = readJson(USERS_FILE);

  const existingIndex = users.findIndex(u => u.username === "cashier");

if (existingIndex !== -1) {
  users.splice(existingIndex, 1);
}

  const credentials = hashPassword("Cashier123!");

  const cashier = {
    id: crypto.randomUUID(),
    username: "cashier",
    role: "cashier",
    salt: credentials.salt,
    hash: credentials.hash,
    createdAt: new Date().toISOString()
  };

  users.push(cashier);

  writeJsonAtomic(USERS_FILE, users);

  return send(res, 200, {
    ok: true,
    username: "cashier",
    password: "Cashier123!"
  });
}
  return send(res, 404, { error: "Not found" });
}

initFiles();

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/api/")) {
    handleApi(req, res).catch(error => {
      console.error(error);
      send(res, 500, { error: "Server error" });
    });
    return;
  }
  serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log(`POS Control running at http://localhost:${PORT}/pos-system.html`);
  if (SESSION_SECRET === "CHANGE_THIS_SECRET_BEFORE_LIVE") {
    console.log("WARNING: set SESSION_SECRET before live deployment.");
  }
});
