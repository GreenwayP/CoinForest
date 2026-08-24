import crypto from "node:crypto";
import { neon } from "@neondatabase/serverless";

const sql = neon(process.env.DATABASE_URL);

const headers = {
  "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, X-Admin-Reset-Key",
  "Access-Control-Allow-Methods":
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
};

/* =====================================================
   RESPONSE HELPERS
===================================================== */

function response(status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function ok(data = {}) {
  return response(200, {
    success: true,
    ...data
  });
}

function bad(status, error, extra = {}) {
  return response(status, {
    success: false,
    error,
    ...extra
  });
}

/* =====================================================
   BASIC HELPERS
===================================================== */

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function createToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const derivedKey = crypto.scryptSync(
    String(password),
    salt,
    64
  );

  return `${salt}:${derivedKey.toString("hex")}`;
}

function verifyPassword(password, storedHash) {
  try {
    const [salt, key] = String(storedHash).split(":");

    if (!salt || !key) return false;

    const derivedKey = crypto.scryptSync(
      String(password),
      salt,
      64
    );

    const storedBuffer = Buffer.from(key, "hex");

    if (storedBuffer.length !== derivedKey.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      derivedKey,
      storedBuffer
    );
  } catch {
    return false;
  }
}

function bearer(request) {
  const value =
    request.headers.get("authorization") || "";

  if (!value.startsWith("Bearer ")) {
    return null;
  }

  return value.slice(7).trim();
}

function getSiteUrl(request) {
  const host =
    request.headers.get("x-forwarded-host") ||
    request.headers.get("host");

  if (!host) {
    return "https://coinforest.vercel.app";
  }

  return `https://${String(host)
    .split(",")[0]
    .trim()}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function jsonBody(request) {
  return request.json().catch(() => ({}));
}

function numberValue(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function cleanLimit(value, fallback = 100) {
  const n = Number(value);

  if (!Number.isFinite(n)) {
    return fallback;
  }

  return Math.min(
    Math.max(Math.floor(n), 1),
    500
  );
}

function pathParts(path) {
  return path
    .split("/")
    .filter(Boolean);
}

/* =====================================================
   SAFE DATABASE HELPERS
===================================================== */

async function tableExists(tableName) {
  try {
    const rows = await sql`
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = ${tableName}
      ) AS exists
    `;

    return !!rows[0]?.exists;
  } catch {
    return false;
  }
}

async function columnExists(tableName, columnName) {
  try {
    const rows = await sql`
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = ${tableName}
          AND column_name = ${columnName}
      ) AS exists
    `;

    return !!rows[0]?.exists;
  } catch {
    return false;
  }
}

/* =====================================================
   EMAIL
===================================================== */

async function sendEmail({ to, subject, html }) {
  const apiKey = process.env.RESEND_API_KEY;

  if (!apiKey) {
    throw new Error(
      "RESEND_API_KEY is not configured."
    );
  }

  const result = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from:
          process.env.EMAIL_FROM ||
          "CoinForest <onboarding@resend.dev>",
        to: [to],
        subject,
        html
      })
    }
  );

  const data = await result.json();

  if (!result.ok) {
    throw new Error(
      data?.message ||
        data?.error ||
        "Unable to send email."
    );
  }

  return data;
}

async function createEmailToken(
  userId,
  tokenType,
  expiresMinutes
) {
  const rawToken = createToken();
  const tokenHash = hashToken(rawToken);

  await sql`
    UPDATE auth_email_tokens
    SET used_at = NOW()
    WHERE user_id = ${userId}
      AND token_type = ${tokenType}
      AND used_at IS NULL
  `;

  await sql`
    INSERT INTO auth_email_tokens (
      id,
      user_id,
      token_hash,
      token_type,
      expires_at,
      created_at
    )
    VALUES (
      ${crypto.randomUUID()},
      ${userId},
      ${tokenHash},
      ${tokenType},
      NOW() +
        (${expiresMinutes} * INTERVAL '1 minute'),
      NOW()
    )
  `;

  return rawToken;
}

async function sendVerificationEmail(request, user) {
  const token = await createEmailToken(
    user.id,
    "email_verification",
    60 * 24
  );

  const verificationUrl =
    `${getSiteUrl(request)}` +
    `/verify-email.html?token=` +
    encodeURIComponent(token);

  const firstName =
    String(user.first_name || "Customer").trim();

  return sendEmail({
    to: user.email,
    subject: "Confirm your CoinForest account",
    html: `
      <div style="
        max-width:600px;
        margin:40px auto;
        background:#ffffff;
        border-radius:18px;
        overflow:hidden;
        font-family:Arial,Helvetica,sans-serif;
        color:#172033;
        box-shadow:0 10px 35px rgba(0,0,0,.08);
      ">
        <div style="
          background:#0b2037;
          padding:28px;
          text-align:center;
        ">
          <div style="
            color:#ffffff;
            font-size:28px;
            font-weight:800;
          ">
            Coin<span style="color:#2ecc71;">
              Forest
            </span>
          </div>
        </div>

        <div style="padding:35px;">
          <h2>Confirm your account</h2>

          <p>
            Hello ${escapeHtml(firstName)},
          </p>

          <p style="line-height:1.7;">
            Thank you for creating your
            CoinForest account.
            Please confirm your email address
            to activate your account.
          </p>

          <div style="
            text-align:center;
            margin:30px 0;
          ">
            <a
              href="${verificationUrl}"
              style="
                display:inline-block;
                background:#2ecc71;
                color:#06140c;
                text-decoration:none;
                font-weight:800;
                padding:14px 24px;
                border-radius:10px;
              "
            >
              Confirm My Account
            </a>
          </div>

          <p style="
            font-size:13px;
            color:#7a8795;
          ">
            This confirmation link expires in 24 hours.
          </p>
        </div>
      </div>
    `
  });
}

/* =====================================================
   REGISTER
===================================================== */

async function register(request, body) {
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const firstName = String(body.first_name || "").trim();
  const lastName = String(body.last_name || "").trim();
  const username = String(body.username || "").trim();

  if (!email || !password) {
    return bad(400, "Email and password are required.");
  }

  if (!firstName) {
    return bad(400, "First name is required.");
  }

  if (!lastName) {
    return bad(400, "Last name is required.");
  }

  if (!username) {
    return bad(400, "Username is required.");
  }

  if (password.length < 6) {
    return bad(
      400,
      "Password must contain at least 6 characters."
    );
  }

  const existingEmail = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(email) = ${email}
    LIMIT 1
  `;

  if (existingEmail.length) {
    return bad(
      409,
      "An account with this email already exists."
    );
  }

  const existingUsername = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(username) = LOWER(${username})
    LIMIT 1
  `;

  if (existingUsername.length) {
    return bad(
      409,
      "That username is already in use."
    );
  }

  const id = crypto.randomUUID();
  const passwordHash = hashPassword(password);

  await sql`
    INSERT INTO profiles (
      id,
      role_id,
      first_name,
      last_name,
      username,
      email,
      status,
      kyc_status,
      two_factor_enabled,
      email_verified_at,
      created_at,
      updated_at
    )
    VALUES (
      ${id},
      '9dbe97ec-7b11-4789-b31b-bff00bc2483e',
      ${firstName},
      ${lastName},
      ${username},
      ${email},
      'active',
      'pending',
      false,
      NULL,
      NOW(),
      NOW()
    )
  `;

  await sql`
    INSERT INTO auth_credentials (
      user_id,
      password_hash,
      password_updated_at,
      failed_login_attempts,
      locked_until,
      created_at,
      updated_at
    )
    VALUES (
      ${id},
      ${passwordHash},
      NOW(),
      0,
      NULL,
      NOW(),
      NOW()
    )
  `;

  const user = {
    id,
    email,
    first_name: firstName,
    last_name: lastName,
    username
  };

  try {
    await sendVerificationEmail(request, user);
  } catch (error) {
    console.error("Verification email error:", error);

    return response(201, {
      success: true,
      email_sent: false,
      message:
        "Account created, but the confirmation email could not be sent.",
      user
    });
  }

  return response(201, {
    success: true,
    email_sent: true,
    message:
      "Account created. Please check your email to confirm your account.",
    user
  });
}

/* =====================================================
   LOGIN
===================================================== */

async function login(body) {
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    return bad(400, "Email and password are required.");
  }

  const result = await sql`
    SELECT
      p.id,
      p.email,
      p.first_name,
      p.last_name,
      p.username,
      p.role_id,
      p.email_verified_at,
      p.status,
      a.password_hash,
      a.failed_login_attempts,
      a.locked_until,
      r.name AS role_name
    FROM profiles p
    INNER JOIN auth_credentials a
      ON a.user_id = p.id
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE LOWER(p.email) = ${email}
    LIMIT 1
  `;

  if (!result.length) {
    return bad(401, "Invalid email or password.");
  }

  const user = result[0];

  if (
    user.locked_until &&
    new Date(user.locked_until) > new Date()
  ) {
    return response(423, {
      success: false,
      error:
        "Account temporarily locked. Please try again later."
    });
  }

  if (!verifyPassword(password, user.password_hash)) {
    const attempts =
      Number(user.failed_login_attempts || 0) + 1;

    if (attempts >= 5) {
      await sql`
        UPDATE auth_credentials
        SET
          failed_login_attempts = 0,
          locked_until = NOW() + INTERVAL '15 minutes',
          updated_at = NOW()
        WHERE user_id = ${user.id}
      `;

      return response(423, {
        success: false,
        error:
          "Too many failed login attempts. Account temporarily locked."
      });
    }

    await sql`
      UPDATE auth_credentials
      SET
        failed_login_attempts = ${attempts},
        updated_at = NOW()
      WHERE user_id = ${user.id}
    `;

    return bad(401, "Invalid email or password.");
  }

  await sql`
    UPDATE auth_credentials
    SET
      failed_login_attempts = 0,
      locked_until = NULL,
      updated_at = NOW()
    WHERE user_id = ${user.id}
  `;

  const token = createToken();

  await sql`
    INSERT INTO user_sessions (
      id,
      user_id,
      session_token_hash,
      status,
      last_activity_at,
      expires_at,
      created_at,
      updated_at
    )
    VALUES (
      ${crypto.randomUUID()},
      ${user.id},
      ${hashToken(token)},
      'active',
      NOW(),
      NOW() + INTERVAL '30 days',
      NOW(),
      NOW()
    )
  `;

  return ok({
    message: "Login successful.",
    token,
    user: {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      role: user.role_name,
      status: user.status,
      email_verified: !!user.email_verified_at
    }
  });
}

/* =====================================================
   AUTHENTICATE
===================================================== */

async function authenticate(request) {
  const token = bearer(request);

  if (!token) {
    return {
      ok: false,
      status: 401,
      error: "Authentication required."
    };
  }

  const tokenHash = hashToken(token);

  const result = await sql`
    SELECT
      p.id,
      p.email,
      p.first_name,
      p.last_name,
      p.username,
      p.role_id,
      p.email_verified_at,
      p.status,
      p.kyc_status,
      r.name AS role_name
    FROM user_sessions s
    INNER JOIN profiles p
      ON p.id = s.user_id
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE
      s.session_token_hash = ${tokenHash}
      AND s.status = 'active'
      AND s.expires_at > NOW()
    LIMIT 1
  `;

  if (!result.length) {
    return {
      ok: false,
      status: 401,
      error: "Invalid or expired session."
    };
  }

  await sql`
    UPDATE user_sessions
    SET
      last_activity_at = NOW(),
      updated_at = NOW()
    WHERE
      session_token_hash = ${tokenHash}
      AND status = 'active'
  `;

  return {
    ok: true,
    user: result[0],
    token
  };
}

async function requireAdmin(request) {
  const auth = await authenticate(request);

  if (!auth.ok) {
    return auth;
  }

  const role =
    String(auth.user.role_name || "").toLowerCase();

  if (
    role !== "admin" &&
    role !== "administrator"
  ) {
    return {
      ok: false,
      status: 403,
      error: "Administrator access required."
    };
  }

  return auth;
}

/* =====================================================
   ME
===================================================== */

async function me(request) {
  const auth = await authenticate(request);

  if (!auth.ok) {
    return bad(auth.status, auth.error);
  }

  const user = auth.user;

  return ok({
    user: {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      role: user.role_name,
      status: user.status,
      kyc_status: user.kyc_status,
      email_verified_at: user.email_verified_at
    }
  });
}

/* =====================================================
   LOGOUT
===================================================== */

async function logout(request) {
  const token = bearer(request);

  if (token) {
    await sql`
      UPDATE user_sessions
      SET
        status = 'revoked',
        revoked_at = NOW(),
        updated_at = NOW()
      WHERE
        session_token_hash = ${hashToken(token)}
        AND status = 'active'
    `;
  }

  return ok({
    message: "Logged out successfully."
  });
}

/* =====================================================
   HEALTH
===================================================== */

async function health() {
  try {
    await sql`SELECT 1`;

    return ok({
      message: "CoinForest API is running.",
      database: true
    });
  } catch (error) {
    console.error("Health database error:", error);

    return response(503, {
      success: false,
      message:
        "CoinForest API is running, but database connection failed.",
      database: false
    });
  }
}

/* =====================================================
   ADMIN DASHBOARD
===================================================== */

async function adminDashboard() {
  const [
    customers,
    pendingKyc,
    investments,
    transactions,
    pendingRequests
  ] = await Promise.all([
    sql`
      SELECT COUNT(*)::int AS count
      FROM profiles p
      LEFT JOIN roles r
        ON r.id = p.role_id
      WHERE LOWER(COALESCE(r.name, 'user'))
        NOT IN ('admin', 'administrator')
    `,

    sql`
      SELECT COUNT(*)::int AS count
      FROM profiles
      WHERE LOWER(COALESCE(kyc_status, 'pending'))
        = 'pending'
    `,

    sql`
      SELECT COUNT(*)::int AS count
      FROM investments
    `,

    sql`
      SELECT COUNT(*)::int AS count
      FROM transactions
    `,

    tableExists("pending_requests")
      ? sql`
          SELECT COUNT(*)::int AS count
          FROM pending_requests
          WHERE LOWER(COALESCE(status, 'pending'))
            = 'pending'
        `
      : Promise.resolve([{ count: 0 }])
  ]);

  return ok({
    stats: {
      customers: customers[0]?.count || 0,
      pending_kyc: pendingKyc[0]?.count || 0,
      investments: investments[0]?.count || 0,
      transactions: transactions[0]?.count || 0,
      pending_requests:
        pendingRequests[0]?.count || 0
    }
  });
}

/* =====================================================
   ADMIN CUSTOMERS — LIST
===================================================== */

async function adminCustomers(url) {
  const search =
    String(url.searchParams.get("search") || "").trim();

  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  const offset =
    Math.max(
      Number(url.searchParams.get("offset") || 0),
      0
    );

  const rows = await sql`
    SELECT
      p.id,
      p.first_name,
      p.last_name,
      p.username,
      p.email,
      p.status,
      p.kyc_status,
      p.email_verified_at,
      p.two_factor_enabled,
      p.created_at,
      p.updated_at,
      r.name AS role
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE
      LOWER(COALESCE(r.name, 'user'))
        NOT IN ('admin', 'administrator')
      AND (
        ${search} = ''
        OR LOWER(COALESCE(p.first_name, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(COALESCE(p.last_name, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(COALESCE(p.username, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(COALESCE(p.email, ''))
          LIKE LOWER(${"%" + search + "%"})
      )
    ORDER BY p.created_at DESC
    LIMIT ${limit}
    OFFSET ${offset}
  `;

  const countRows = await sql`
    SELECT COUNT(*)::int AS count
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE
      LOWER(COALESCE(r.name, 'user'))
        NOT IN ('admin', 'administrator')
      AND (
        ${search} = ''
        OR LOWER(COALESCE(p.first_name, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(COALESCE(p.last_name, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(COALESCE(p.username, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(COALESCE(p.email, ''))
          LIKE LOWER(${"%" + search + "%"})
      )
  `;

  return ok({
    customers: rows,
    total: countRows[0]?.count || 0,
    limit,
    offset
  });
}

/* =====================================================
   ADMIN CUSTOMER — VIEW
   Supports all of:
   /api/admin/customers?id=...
   /api/admin/customers/:id
   /api/admin/customer/:id
===================================================== */

async function adminCustomer(id) {
  if (!id) {
    return bad(400, "Customer ID is required.");
  }

  const result = await sql`
    SELECT
      p.*,
      r.name AS role
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE p.id = ${id}
    LIMIT 1
  `;

  if (!result.length) {
    return bad(404, "Customer not found.");
  }

  const customer = result[0];

  let wallets = [];

  try {
    wallets = await sql`
      SELECT *
      FROM wallets
      WHERE user_id = ${id}
      ORDER BY created_at ASC
    `;
  } catch (error) {
    console.warn(
      "Customer wallet lookup warning:",
      error?.message
    );
  }

  let kyc = [];

  if (await tableExists("kyc_submissions")) {
    try {
      kyc = await sql`
        SELECT *
        FROM kyc_submissions
        WHERE user_id = ${id}
        ORDER BY created_at DESC
      `;
    } catch (error) {
      console.warn(
        "Customer KYC lookup warning:",
        error?.message
      );
    }
  }

  return ok({
    customer,
    wallets,
    kyc,
    account: customer,
    wallet: wallets[0] || null
  });
}

/* =====================================================
   ADMIN CUSTOMER ACCOUNT ACTIONS
   APPROVE / DECLINE / SUSPEND / ACTIVATE
===================================================== */

async function updateCustomerStatus(
  request,
  id,
  body,
  forcedStatus = null
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(admin.status, admin.error);
  }

  if (!id) {
    return bad(400, "Customer ID is required.");
  }

  let action =
    forcedStatus ||
    body.status ||
    body.action ||
    body.decision ||
    "";

  action =
    String(action)
      .trim()
      .toLowerCase();

  const statusMap = {
    approve: "active",
    approved: "active",
    activate: "active",
    active: "active",

    decline: "disabled",
    declined: "disabled",
    reject: "disabled",
    rejected: "disabled",

    suspend: "suspended",
    suspended: "suspended",

    disable: "disabled",
    disabled: "disabled"
  };

  const nextStatus =
    statusMap[action];

  if (!nextStatus) {
    return bad(
      400,
      "Invalid account action. Use approve, decline, suspend, activate, or disable."
    );
  }

  const existing = await sql`
    SELECT
      p.*,
      r.name AS role
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE p.id = ${id}
    LIMIT 1
  `;

  if (!existing.length) {
    return bad(404, "Customer not found.");
  }

  if (
    String(existing[0].role || "").toLowerCase() ===
    "admin"
  ) {
    return bad(
      403,
      "Administrator account cannot be changed here."
    );
  }

  const updated = await sql`
    UPDATE profiles
    SET
      status = ${nextStatus},
      updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `;

  return ok({
    message:
      `Customer account ${action} successfully.`,
    customer: updated[0],
    status: nextStatus
  });
}

/* =====================================================
   ADMIN WALLETS — LIST
===================================================== */

async function adminWallets(url) {
  const search =
    String(
      url.searchParams.get("search") || ""
    ).trim();

  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  const rows = await sql`
    SELECT
      w.*,
      p.first_name,
      p.last_name,
      p.username,
      p.email,
      p.status AS customer_status,
      p.kyc_status
    FROM wallets w
    INNER JOIN profiles p
      ON p.id = w.user_id
    WHERE
      ${search} = ''
      OR LOWER(COALESCE(p.username, ''))
        LIKE LOWER(${"%" + search + "%"})
      OR LOWER(COALESCE(p.email, ''))
        LIKE LOWER(${"%" + search + "%"})
      OR LOWER(COALESCE(p.first_name, ''))
        LIKE LOWER(${"%" + search + "%"})
      OR LOWER(COALESCE(p.last_name, ''))
        LIKE LOWER(${"%" + search + "%"})
    ORDER BY w.created_at DESC
    LIMIT ${limit}
  `;

  return ok({
    wallets: rows
  });
}

/* =====================================================
   ADMIN CUSTOMER WALLET
===================================================== */

async function adminWallet(userId) {
  if (!userId) {
    return bad(400, "User ID is required.");
  }

  const customer = await sql`
    SELECT id, first_name, last_name,
           username, email, status, kyc_status
    FROM profiles
    WHERE id = ${userId}
    LIMIT 1
  `;

  if (!customer.length) {
    return bad(404, "Customer not found.");
  }

  let wallets = [];

  try {
    wallets = await sql`
      SELECT *
      FROM wallets
      WHERE user_id = ${userId}
      ORDER BY created_at ASC
    `;
  } catch (error) {
    console.error(
      "Wallet lookup error:",
      error
    );

    return bad(
      500,
      "Unable to load customer wallets.",
      {
        details: error?.message || ""
      }
    );
  }

  let ledger = [];

  if (await tableExists("wallet_ledger")) {
    try {
      ledger = await sql`
        SELECT *
        FROM wallet_ledger
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
        LIMIT 200
      `;
    } catch (error) {
      console.warn(
        "wallet_ledger unavailable:",
        error?.message
      );
    }
  }

  return ok({
    customer: customer[0],
    wallets,
    wallet: wallets[0] || null,
    ledger
  });
}

/* =====================================================
   ADMIN WALLET ADJUSTMENT
===================================================== */

async function adjustWallet(request, body) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(admin.status, admin.error);
  }

  const userId =
    String(
      body.user_id ||
      body.customer_id ||
      body.id ||
      ""
    ).trim();

  const walletType =
    String(
      body.wallet_type ||
      body.wallet ||
      "main"
    )
      .trim()
      .toLowerCase();

  const amount =
    numberValue(body.amount, NaN);

  const reason =
    String(
      body.reason ||
      body.description ||
      "Administrator balance adjustment"
    ).trim();

  if (!userId) {
    return bad(400, "User ID is required.");
  }

  if (!Number.isFinite(amount) || amount === 0) {
    return bad(
      400,
      "A non-zero adjustment amount is required."
    );
  }

  if (
    walletType !== "main" &&
    walletType !== "profit"
  ) {
    return bad(
      400,
      "Wallet must be main or profit."
    );
  }

  const walletRows = await sql`
    SELECT *
    FROM wallets
    WHERE user_id = ${userId}
    ORDER BY created_at ASC
  `;

  if (!walletRows.length) {
    return bad(
      404,
      "Customer wallet not found."
    );
  }

  let wallet =
    walletRows.find(
      w =>
        String(w.wallet_type || "").toLowerCase() ===
        walletType
    ) || walletRows[0];

  const balanceColumn =
    walletType === "profit"
      ? "profit_balance"
      : "main_balance";

  /*
   * CoinForest's current wallet foundation uses
   * main_balance / profit_balance.
   *
   * This also handles a wallet schema where a row
   * represents a wallet type and has a normal
   * balance column.
   */

  let current;

  if (
    wallet[balanceColumn] !== undefined &&
    wallet[balanceColumn] !== null
  ) {
    current =
      numberValue(
        wallet[balanceColumn],
        0
      );
  } else if (
    wallet.balance !== undefined &&
    wallet.balance !== null
  ) {
    current =
      numberValue(
        wallet.balance,
        0
      );
  } else {
    current = 0;
  }

  const next = current + amount;

  if (next < 0) {
    return bad(
      400,
      "Insufficient wallet balance."
    );
  }

  let updated;

  if (
    wallet[balanceColumn] !== undefined
  ) {
    if (walletType === "profit") {
      updated = await sql`
        UPDATE wallets
        SET
          profit_balance = ${next},
          updated_at = NOW()
        WHERE id = ${wallet.id}
        RETURNING *
      `;
    } else {
      updated = await sql`
        UPDATE wallets
        SET
          main_balance = ${next},
          updated_at = NOW()
        WHERE id = ${wallet.id}
        RETURNING *
      `;
    }
  } else {
    updated = await sql`
      UPDATE wallets
      SET
        balance = ${next},
        updated_at = NOW()
      WHERE id = ${wallet.id}
      RETURNING *
    `;
  }

  if (await tableExists("wallet_ledger")) {
    try {
      await sql`
        INSERT INTO wallet_ledger (
          id,
          user_id,
          wallet_type,
          amount,
          balance_before,
          balance_after,
          entry_type,
          description,
          created_by,
          created_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${userId},
          ${walletType},
          ${amount},
          ${current},
          ${next},
          'admin_adjustment',
          ${reason},
          ${admin.user.id},
          NOW()
        )
      `;
    } catch (error) {
      console.warn(
        "wallet_ledger insert failed:",
        error?.message
      );
    }
  }

  return ok({
    message:
      "Wallet balance updated successfully.",
    wallet:
      updated[0],
    balance_before: current,
    balance_after: next
  });
}

/* =====================================================
   KYC LIST
===================================================== */

async function adminKyc(url) {
  const status =
    String(
      url.searchParams.get("status") || ""
    )
      .trim()
      .toLowerCase();

  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  /*
   * IMPORTANT:
   * Do not return zero simply because the
   * kyc_submissions table has no rows.
   *
   * The Admin needs to see accounts whose
   * profile.kyc_status is pending.
   */

  if (!(await tableExists("kyc_submissions"))) {
    const profiles = await sql`
      SELECT
        p.id AS user_id,
        p.first_name,
        p.last_name,
        p.username,
        p.email,
        p.status AS account_status,
        p.kyc_status,
        p.created_at,
        NULL::text AS submission_status,
        NULL::timestamp AS submitted_at
      FROM profiles p
      LEFT JOIN roles r
        ON r.id = p.role_id
      WHERE
        LOWER(COALESCE(r.name, 'user'))
          NOT IN ('admin', 'administrator')
        AND (
          ${status} = ''
          OR LOWER(COALESCE(p.kyc_status, 'pending'))
             = ${status}
        )
      ORDER BY p.created_at DESC
      LIMIT ${limit}
    `;

    return ok({
      submissions: profiles,
      kyc: profiles,
      source: "profiles"
    });
  }

  let rows;

  if (status) {
    rows = await sql`
      SELECT
        k.*,
        p.first_name,
        p.last_name,
        p.username,
        p.email,
        p.status AS account_status,
        p.kyc_status
      FROM kyc_submissions k
      INNER JOIN profiles p
        ON p.id = k.user_id
      WHERE LOWER(COALESCE(k.status, 'pending'))
        = ${status}
      ORDER BY k.created_at DESC
      LIMIT ${limit}
    `;
  } else {
    rows = await sql`
      SELECT
        k.*,
        p.first_name,
        p.last_name,
        p.username,
        p.email,
        p.status AS account_status,
        p.kyc_status
      FROM kyc_submissions k
      INNER JOIN profiles p
        ON p.id = k.user_id
      ORDER BY k.created_at DESC
      LIMIT ${limit}
    `;
  }

  /*
   * Add profile-level pending KYC accounts that
   * do not yet have a submission row.
   */

  if (!status || status === "pending") {
    try {
      const existingIds =
        rows
          .map(x => String(x.user_id))
          .filter(Boolean);

      const pendingProfiles =
        await sql`
          SELECT
            p.id AS user_id,
            p.first_name,
            p.last_name,
            p.username,
            p.email,
            p.status AS account_status,
            p.kyc_status,
            p.created_at
          FROM profiles p
          LEFT JOIN roles r
            ON r.id = p.role_id
          WHERE
            LOWER(COALESCE(r.name, 'user'))
              NOT IN ('admin', 'administrator')
            AND LOWER(COALESCE(p.kyc_status, 'pending'))
              = 'pending'
          ORDER BY p.created_at DESC
          LIMIT ${limit}
        `;

      for (const item of pendingProfiles) {
        if (
          !existingIds.includes(
            String(item.user_id)
          )
        ) {
          rows.push({
            ...item,
            status: "pending",
            submission_status: "pending",
            source: "profile"
          });
        }
      }
    } catch (error) {
      console.warn(
        "Profile KYC fallback warning:",
        error?.message
      );
    }
  }

  return ok({
    submissions: rows,
    kyc: rows
  });
}

/* =====================================================
   KYC VIEW
===================================================== */

async function viewKyc(id) {
  if (!id) {
    return bad(400, "KYC ID or customer ID is required.");
  }

  if (await tableExists("kyc_submissions")) {
    const submission = await sql`
      SELECT
        k.*,
        p.first_name,
        p.last_name,
        p.username,
        p.email,
        p.status AS account_status,
        p.kyc_status
      FROM kyc_submissions k
      INNER JOIN profiles p
        ON p.id = k.user_id
      WHERE k.id = ${id}
      LIMIT 1
    `;

    if (submission.length) {
      return ok({
        submission: submission[0],
        kyc: submission[0]
      });
    }
  }

  const profile = await sql`
    SELECT
      p.*,
      r.name AS role
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE p.id = ${id}
    LIMIT 1
  `;

  if (!profile.length) {
    return bad(
      404,
      "KYC record or customer not found."
    );
  }

  let submissions = [];

  if (await tableExists("kyc_submissions")) {
    try {
      submissions = await sql`
        SELECT *
        FROM kyc_submissions
        WHERE user_id = ${id}
        ORDER BY created_at DESC
      `;
    } catch {}
  }

  return ok({
    customer: profile[0],
    kyc: submissions[0] || {
      user_id: id,
      status: profile[0].kyc_status || "pending"
    },
    submissions
  });
}

/* =====================================================
   REVIEW KYC
===================================================== */

async function reviewKyc(request, id, body) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(admin.status, admin.error);
  }

  const decision =
    String(
      body.status ||
      body.decision ||
      ""
    )
      .trim()
      .toLowerCase();

  if (
    decision !== "approved" &&
    decision !== "rejected" &&
    decision !== "declined"
  ) {
    return bad(
      400,
      "KYC decision must be approved or rejected."
    );
  }

  const normalizedDecision =
    decision === "declined"
      ? "rejected"
      : decision;

  if (await tableExists("kyc_submissions")) {
    const submission = await sql`
      SELECT *
      FROM kyc_submissions
      WHERE id = ${id}
      LIMIT 1
    `;

    if (submission.length) {
      const userId =
        submission[0].user_id;

      const updated = await sql`
        UPDATE kyc_submissions
        SET
          status = ${normalizedDecision},
          reviewed_by = ${admin.user.id},
          reviewed_at = NOW(),
          updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;

      await sql`
        UPDATE profiles
        SET
          kyc_status = ${normalizedDecision},
          updated_at = NOW()
        WHERE id = ${userId}
      `;

      return ok({
        message:
          `KYC ${normalizedDecision} successfully.`,
        submission: updated[0]
      });
    }
  }

  /*
   * Fallback:
   * If the Admin is viewing a profile directly,
   * allow the KYC action against profiles.kyc_status.
   */

  const profile = await sql`
    SELECT id
    FROM profiles
    WHERE id = ${id}
    LIMIT 1
  `;

  if (!profile.length) {
    return bad(
      404,
      "KYC submission or customer not found."
    );
  }

  const updatedProfile = await sql`
    UPDATE profiles
    SET
      kyc_status = ${normalizedDecision},
      updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `;

  return ok({
    message:
      `KYC ${normalizedDecision} successfully.`,
    customer: updatedProfile[0]
  });
}

/* =====================================================
   INVESTMENTS
===================================================== */

async function adminInvestments(url) {
  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  const rows = await sql`
    SELECT
      i.*,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM investments i
    INNER JOIN profiles p
      ON p.id = i.user_id
    ORDER BY i.created_at DESC
    LIMIT ${limit}
  `;

  return ok({
    investments: rows
  });
}

/* =====================================================
   TRANSACTIONS
===================================================== */

async function adminTransactions(url) {
  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  const type =
    String(
      url.searchParams.get("type") || ""
    ).trim();

  let rows;

  if (type) {
    rows = await sql`
      SELECT
        t.*,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM transactions t
      INNER JOIN profiles p
        ON p.id = t.user_id
      WHERE LOWER(COALESCE(t.type, ''))
        = LOWER(${type})
      ORDER BY t.created_at DESC
      LIMIT ${limit}
    `;
  } else {
    rows = await sql`
      SELECT
        t.*,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM transactions t
      INNER JOIN profiles p
        ON p.id = t.user_id
      ORDER BY t.created_at DESC
      LIMIT ${limit}
    `;
  }

  return ok({
    transactions: rows
  });
}

/* =====================================================
   PENDING REQUESTS
===================================================== */

async function adminRequests(url) {
  if (!(await tableExists("pending_requests"))) {
    return ok({
      requests: []
    });
  }

  const status =
    String(
      url.searchParams.get("status") ||
      "pending"
    )
      .trim()
      .toLowerCase();

  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  const rows = await sql`
    SELECT
      r.*,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM pending_requests r
    INNER JOIN profiles p
      ON p.id = r.user_id
    WHERE LOWER(COALESCE(r.status, 'pending'))
      = ${status}
    ORDER BY r.created_at DESC
    LIMIT ${limit}
  `;

  return ok({
    requests: rows
  });
}

/* =====================================================
   PROCESS REQUEST
===================================================== */

async function processRequest(
  request,
  id,
  body
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(admin.status, admin.error);
  }

  if (!(await tableExists("pending_requests"))) {
    return bad(
      404,
      "Pending requests table is not available."
    );
  }

  const decision =
    String(
      body.status ||
      body.decision ||
      ""
    )
      .trim()
      .toLowerCase();

  if (
    decision !== "approved" &&
    decision !== "rejected" &&
    decision !== "declined"
  ) {
    return bad(
      400,
      "Decision must be approved or rejected."
    );
  }

  const normalizedDecision =
    decision === "declined"
      ? "rejected"
      : decision;

  const rows = await sql`
    SELECT *
    FROM pending_requests
    WHERE id = ${id}
    LIMIT 1
  `;

  if (!rows.length) {
    return bad(404, "Request not found.");
  }

  const item = rows[0];

  const updated = await sql`
    UPDATE pending_requests
    SET
      status = ${normalizedDecision},
      reviewed_by = ${admin.user.id},
      reviewed_at = NOW(),
      updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `;

  if (
    normalizedDecision === "approved" &&
    item.type &&
    item.user_id
  ) {
    const type =
      String(item.type).toLowerCase();

    const amount =
      numberValue(item.amount, 0);

    if (
      amount > 0 &&
      (
        type === "deposit" ||
        type === "transfer"
      )
    ) {
      try {
        const wallets = await sql`
          SELECT *
          FROM wallets
          WHERE user_id = ${item.user_id}
          ORDER BY created_at ASC
        `;

        if (wallets.length) {
          const wallet = wallets[0];

          if (
            wallet.main_balance !== undefined
          ) {
            const oldBalance =
              numberValue(
                wallet.main_balance,
                0
              );

            await sql`
              UPDATE wallets
              SET
                main_balance =
                  ${oldBalance + amount},
                updated_at = NOW()
              WHERE id = ${wallet.id}
            `;
          } else if (
            wallet.balance !== undefined
          ) {
            const oldBalance =
              numberValue(
                wallet.balance,
                0
              );

            await sql`
              UPDATE wallets
              SET
                balance =
                  ${oldBalance + amount},
                updated_at = NOW()
              WHERE id = ${wallet.id}
            `;
          }
        }
      } catch (error) {
        console.warn(
          "Request wallet processing warning:",
          error?.message
        );
      }
    }
  }

  return ok({
    message:
      `Request ${normalizedDecision} successfully.`,
    request: updated[0]
  });
}

/* =====================================================
   CHAT
===================================================== */

async function adminConversations() {
  /*
   * The old code crashed here when chat_messages
   * was missing. Conversation listing must remain
   * usable independently.
   */

  if (!(await tableExists("chat_conversations"))) {
    return ok({
      conversations: [],
      messages_available:
        await tableExists("chat_messages")
    });
  }

  const rows = await sql`
    SELECT
      c.*,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM chat_conversations c
    INNER JOIN profiles p
      ON p.id = c.user_id
    ORDER BY
      COALESCE(
        c.updated_at,
        c.created_at
      ) DESC
  `;

  return ok({
    conversations: rows,
    messages_available:
      await tableExists("chat_messages")
  });
}

async function adminMessages(conversationId) {
  if (!conversationId) {
    return bad(
      400,
      "Conversation ID is required."
    );
  }

  if (!(await tableExists("chat_messages"))) {
    return ok({
      messages: [],
      available: false,
      message:
        "Chat message storage is not available yet."
    });
  }

  const rows = await sql`
    SELECT *
    FROM chat_messages
    WHERE conversation_id = ${conversationId}
    ORDER BY created_at ASC
  `;

  return ok({
    messages: rows,
    available: true
  });
}

async function adminSendMessage(
  request,
  conversationId,
  body
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(admin.status, admin.error);
  }

  const message =
    String(
      body.message ||
      body.content ||
      ""
    ).trim();

  if (!conversationId) {
    return bad(
      400,
      "Conversation ID is required."
    );
  }

  if (!message) {
    return bad(
      400,
      "Message cannot be empty."
    );
  }

  if (!(await tableExists("chat_conversations"))) {
    return bad(
      503,
      "Chat conversations are not available."
    );
  }

  if (!(await tableExists("chat_messages"))) {
    return bad(
      503,
      "Chat messages table is not available."
    );
  }

  const conversation = await sql`
    SELECT id
    FROM chat_conversations
    WHERE id = ${conversationId}
    LIMIT 1
  `;

  if (!conversation.length) {
    return bad(
      404,
      "Conversation not found."
    );
  }

  const id = crypto.randomUUID();

  /*
   * Support the existing message column.
   * If the database uses content instead, use it.
   */

  const hasMessage =
    await columnExists(
      "chat_messages",
      "message"
    );

  const hasContent =
    await columnExists(
      "chat_messages",
      "content"
    );

  let rows;

  if (hasMessage) {
    rows = await sql`
      INSERT INTO chat_messages (
        id,
        conversation_id,
        sender_id,
        sender_type,
        message,
        created_at
      )
      VALUES (
        ${id},
        ${conversationId},
        ${admin.user.id},
        'admin',
        ${message},
        NOW()
      )
      RETURNING *
    `;
  } else if (hasContent) {
    rows = await sql`
      INSERT INTO chat_messages (
        id,
        conversation_id,
        sender_id,
        sender_type,
        content,
        created_at
      )
      VALUES (
        ${id},
        ${conversationId},
        ${admin.user.id},
        'admin',
        ${message},
        NOW()
      )
      RETURNING *
    `;
  } else {
    return bad(
      500,
      "Chat messages table does not contain a message/content column."
    );
  }

  if (
    await columnExists(
      "chat_conversations",
      "updated_at"
    )
  ) {
    await sql`
      UPDATE chat_conversations
      SET updated_at = NOW()
      WHERE id = ${conversationId}
    `;
  }

  return ok({
    message: "Message sent.",
    data: rows[0]
  });
}

/* =====================================================
   ADMIN ACTIVITY
===================================================== */

async function adminActivity() {
  const activities = [];

  try {
    const rows = await sql`
      SELECT
        id,
        'transaction' AS activity_type,
        type AS action,
        amount,
        user_id,
        created_at
      FROM transactions
      ORDER BY created_at DESC
      LIMIT 20
    `;

    activities.push(...rows);
  } catch {}

  try {
    const rows = await sql`
      SELECT
        id,
        'investment' AS activity_type,
        'investment_created' AS action,
        amount,
        user_id,
        created_at
      FROM investments
      ORDER BY created_at DESC
      LIMIT 20
    `;

    activities.push(...rows);
  } catch {}

  activities.sort(
    (a, b) =>
      new Date(b.created_at) -
      new Date(a.created_at)
  );

  return ok({
    activity: activities.slice(0, 30)
  });
}

/* =====================================================
   UPDATE CUSTOMER
===================================================== */

async function updateCustomer(
  request,
  id,
  body
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(admin.status, admin.error);
  }

  if (!id) {
    return bad(
      400,
      "Customer ID is required."
    );
  }

  const current = await sql`
    SELECT id
    FROM profiles
    WHERE id = ${id}
    LIMIT 1
  `;

  if (!current.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  const firstName =
    body.first_name !== undefined
      ? String(body.first_name).trim()
      : null;

  const lastName =
    body.last_name !== undefined
      ? String(body.last_name).trim()
      : null;

  const username =
    body.username !== undefined
      ? String(body.username).trim()
      : null;

  const status =
    body.status !== undefined
      ? String(body.status).trim()
      : null;

  const kycStatus =
    body.kyc_status !== undefined
      ? String(body.kyc_status).trim()
      : null;

  const updated = await sql`
    UPDATE profiles
    SET
      first_name =
        COALESCE(${firstName}, first_name),
      last_name =
        COALESCE(${lastName}, last_name),
      username =
        COALESCE(${username}, username),
      status =
        COALESCE(${status}, status),
      kyc_status =
        COALESCE(${kycStatus}, kyc_status),
      updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `;

  return ok({
    message:
      "Customer updated successfully.",
    customer: updated[0]
  });
}

/* =====================================================
   ADMIN PASSWORD RESET
===================================================== */

async function resetAdminPassword(
  request,
  body
) {
  const resetKey =
    request.headers.get("x-admin-reset-key");

  const configuredKey =
    process.env.ADMIN_RESET_KEY;

  if (
    !configuredKey ||
    resetKey !== configuredKey
  ) {
    return bad(403, "Unauthorized.");
  }

  const email =
    normalizeEmail(body.email);

  const password =
    String(body.password || "");

  if (!email || !password) {
    return bad(
      400,
      "Email and password are required."
    );
  }

  if (password.length < 6) {
    return bad(
      400,
      "Password must contain at least 6 characters."
    );
  }

  const passwordHash =
    hashPassword(password);

  const result = await sql`
    UPDATE auth_credentials
    SET
      password_hash = ${passwordHash},
      password_updated_at = NOW(),
      failed_login_attempts = 0,
      locked_until = NULL,
      updated_at = NOW()
    WHERE user_id = (
      SELECT p.id
      FROM profiles p
      INNER JOIN roles r
        ON r.id = p.role_id
      WHERE
        LOWER(p.email) = ${email}
        AND LOWER(r.name) = 'admin'
      LIMIT 1
    )
    RETURNING user_id
  `;

  if (!result.length) {
    return bad(
      404,
      "Admin account not found."
    );
  }

  return ok({
    message:
      "Admin password reset successfully."
  });
}

/* =====================================================
   EMAIL VERIFICATION
===================================================== */

async function verifyEmail(token) {
  const cleanToken =
    String(token || "").trim();

  if (!cleanToken) {
    return bad(
      400,
      "Verification token is required."
    );
  }

  const tokenHash =
    hashToken(cleanToken);

  const result = await sql`
    SELECT
      t.id AS token_id,
      t.user_id
    FROM auth_email_tokens t
    WHERE
      t.token_hash = ${tokenHash}
      AND t.token_type = 'email_verification'
      AND t.used_at IS NULL
      AND t.expires_at > NOW()
    LIMIT 1
  `;

  if (!result.length) {
    return bad(
      400,
      "This verification link is invalid or has expired."
    );
  }

  const item = result[0];

  await sql`
    UPDATE profiles
    SET
      email_verified_at = NOW(),
      updated_at = NOW()
    WHERE id = ${item.user_id}
  `;

  await sql`
    UPDATE auth_email_tokens
    SET used_at = NOW()
    WHERE id = ${item.token_id}
  `;

  return ok({
    message:
      "Your email has been confirmed successfully."
  });
}

/* =====================================================
   NODE REQUEST → WEB REQUEST
===================================================== */

function createWebRequest(req) {
  const protocol =
    String(
      req.headers["x-forwarded-proto"] ||
      "https"
    )
      .split(",")[0]
      .trim();

  const host =
    String(
      req.headers["x-forwarded-host"] ||
      req.headers.host ||
      "coinforest.vercel.app"
    )
      .split(",")[0]
      .trim();

  const rawUrl =
    String(req.url || "/");

  const absoluteUrl =
    rawUrl.startsWith("http://") ||
    rawUrl.startsWith("https://")
      ? rawUrl
      : `${protocol}://${host}${rawUrl}`;

  const requestHeaders =
    new Headers();

  for (
    const [key, value] of Object.entries(
      req.headers || {}
    )
  ) {
    if (Array.isArray(value)) {
      requestHeaders.set(
        key,
        value.join(", ")
      );
    } else if (
      value !== undefined
    ) {
      requestHeaders.set(
        key,
        String(value)
      );
    }
  }

  let body;

  if (
    req.method !== "GET" &&
    req.method !== "HEAD"
  ) {
    if (
      req.body !== undefined &&
      req.body !== null
    ) {
      if (typeof req.body === "string") {
        body = req.body;
      } else if (Buffer.isBuffer(req.body)) {
        body = req.body;
      } else {
        body = JSON.stringify(req.body);

        if (
          !requestHeaders.has(
            "content-type"
          )
        ) {
          requestHeaders.set(
            "content-type",
            "application/json"
          );
        }
      }
    }
  }

  return new Request(
    absoluteUrl,
    {
      method: req.method || "GET",
      headers: requestHeaders,
      body
    }
  );
}

/* =====================================================
   WEB RESPONSE → NODE RESPONSE
===================================================== */

async function writeWebResponse(
  res,
  webResponse
) {
  if (res.headersSent) return;

  res.statusCode =
    webResponse.status;

  webResponse.headers.forEach(
    (value, key) => {
      res.setHeader(
        key,
        value
      );
    }
  );

  const body =
    await webResponse.text();

  res.end(body);
}

/* =====================================================
   MAIN ROUTER
===================================================== */

export default async function handler(
  req,
  res
) {
  try {
    const request =
      createWebRequest(req);

    if (
      request.method === "OPTIONS"
    ) {
      res.statusCode = 204;

      res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
      );

      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, X-Admin-Reset-Key"
      );

      res.setHeader(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, PATCH, DELETE, OPTIONS"
      );

      res.end();
      return;
    }

    const url =
      new URL(request.url);

    const path =
      url.pathname;

    const method =
      request.method.toUpperCase();

    const parts =
      pathParts(path);

    /* =================================================
       HEALTH
    ================================================= */

    if (
      method === "GET" &&
      path === "/api/health"
    ) {
      return writeWebResponse(
        res,
        await health()
      );
    }

    /* =================================================
       AUTH REGISTER
    ================================================= */

    if (
      method === "POST" &&
      path === "/api/auth/register"
    ) {
      return writeWebResponse(
        res,
        await register(
          request,
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       AUTH LOGIN
    ================================================= */

    if (
      method === "POST" &&
      path === "/api/auth/login"
    ) {
      return writeWebResponse(
        res,
        await login(
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       VERIFY EMAIL
    ================================================= */

    if (
      method === "POST" &&
      path === "/api/auth/verify-email"
    ) {
      const body =
        await jsonBody(request);

      return writeWebResponse(
        res,
        await verifyEmail(body.token)
      );
    }

    /* =================================================
       LOGOUT
    ================================================= */

    if (
      method === "POST" &&
      path === "/api/auth/logout"
    ) {
      return writeWebResponse(
        res,
        await logout(request)
      );
    }

    /* =================================================
       CURRENT USER
    ================================================= */

    if (
      method === "GET" &&
      path === "/api/auth/me"
    ) {
      return writeWebResponse(
        res,
        await me(request)
      );
    }

    /* =================================================
       ADMIN PASSWORD RESET
    ================================================= */

    if (
      method === "POST" &&
      path === "/api/admin/reset-password"
    ) {
      return writeWebResponse(
        res,
        await resetAdminPassword(
          request,
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       ADMIN DASHBOARD
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/dashboard" ||
        path === "/api/admin/stats"
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      return writeWebResponse(
        res,
        await adminDashboard()
      );
    }

    /* =================================================
       ADMIN ACTIVITY
    ================================================= */

    if (
      method === "GET" &&
      path === "/api/admin/activity"
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      return writeWebResponse(
        res,
        await adminActivity()
      );
    }

    /* =================================================
       ADMIN CUSTOMERS — LIST
       Added compatibility aliases.
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/customers" ||
        path === "/api/admin/users"
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      const id =
        url.searchParams.get("id") ||
        url.searchParams.get("user_id") ||
        url.searchParams.get("customer_id");

      if (id) {
        return writeWebResponse(
          res,
          await adminCustomer(id)
        );
      }

      return writeWebResponse(
        res,
        await adminCustomers(url)
      );
    }

    /* =================================================
       ADMIN CUSTOMER — VIEW
       NEW ROUTES
    ================================================= */

    if (
      method === "GET" &&
      (
        path.startsWith("/api/admin/customers/") ||
        path.startsWith("/api/admin/customer/") ||
        path.startsWith("/api/admin/users/")
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      const id =
        parts[parts.length - 1];

      if (
        id &&
        id !== "customers" &&
        id !== "customer" &&
        id !== "users"
      ) {
        return writeWebResponse(
          res,
          await adminCustomer(id)
        );
      }
    }

    /* =================================================
       ADMIN CUSTOMER ACCOUNT ACTION
       APPROVE / DECLINE / SUSPEND
    ================================================= */

    if (
      (
        method === "POST" ||
        method === "PUT" ||
        method === "PATCH"
      ) &&
      (
        path.includes("/approve") ||
        path.includes("/decline") ||
        path.includes("/reject") ||
        path.includes("/suspend") ||
        path.includes("/activate") ||
        path.includes("/disable")
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      const action =
        parts[parts.length - 1];

      const actionIndex =
        parts.findIndex(
          x =>
            [
              "approve",
              "decline",
              "reject",
              "suspend",
              "activate",
              "disable"
            ].includes(x)
        );

      const id =
        actionIndex > 0
          ? parts[actionIndex - 1]
          : null;

      return writeWebResponse(
        res,
        await updateCustomerStatus(
          request,
          id,
          await jsonBody(request),
          action
        )
      );
    }

    /* =================================================
       ADMIN CUSTOMER UPDATE
    ================================================= */

    if (
      (
        method === "PUT" ||
        method === "PATCH"
      ) &&
      (
        path.startsWith(
          "/api/admin/customers/"
        ) ||
        path.startsWith(
          "/api/admin/customer/"
        ) ||
        path.startsWith(
          "/api/admin/users/"
        )
      )
    ) {
      const id =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await updateCustomer(
          request,
          id,
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       ADMIN WALLETS — LIST
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/wallets" ||
        path === "/api/admin/wallet"
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      const userId =
        url.searchParams.get("user_id") ||
        url.searchParams.get("customer_id") ||
        url.searchParams.get("id");

      if (userId) {
        return writeWebResponse(
          res,
          await adminWallet(userId)
        );
      }

      return writeWebResponse(
        res,
        await adminWallets(url)
      );
    }

    /* =================================================
       ADMIN CUSTOMER WALLET VIEW
       NEW COMPATIBILITY ROUTES
    ================================================= */

    if (
      method === "GET" &&
      (
        path.startsWith(
          "/api/admin/customer-wallet/"
        ) ||
        path.startsWith(
          "/api/admin/customers/"
        ) &&
        path.endsWith("/wallet")
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      let userId = null;

      if (
        path.startsWith(
          "/api/admin/customer-wallet/"
        )
      ) {
        userId =
          parts[parts.length - 1];
      } else {
        const walletIndex =
          parts.lastIndexOf("wallet");

        userId =
          walletIndex > 0
            ? parts[walletIndex - 1]
            : null;
      }

      return writeWebResponse(
        res,
        await adminWallet(userId)
      );
    }

    /* =================================================
       ADMIN WALLET ADJUSTMENT
       Multiple aliases retained.
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/admin/wallets/adjust" ||
        path === "/api/admin/wallet/adjust" ||
        path === "/api/admin/customer-wallet/adjust"
      )
    ) {
      return writeWebResponse(
        res,
        await adjustWallet(
          request,
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       ADMIN CUSTOMER WALLET ADJUSTMENT
       /customers/:id/wallet/adjust
    ================================================= */

    if (
      method === "POST" &&
      path.startsWith(
        "/api/admin/customers/"
      ) &&
      path.endsWith("/wallet/adjust")
    ) {
      const body =
        await jsonBody(request);

      const walletParts =
        pathParts(path);

      const adjustIndex =
        walletParts.lastIndexOf("adjust");

      const userId =
        adjustIndex >= 2
          ? walletParts[adjustIndex - 2]
          : null;

      return writeWebResponse(
        res,
        await adjustWallet(
          request,
          {
            ...body,
            user_id:
              body.user_id ||
              userId
          }
        )
      );
    }

    /* =================================================
       ADMIN KYC LIST
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/kyc" ||
        path === "/api/admin/kyc-submissions"
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      return writeWebResponse(
        res,
        await adminKyc(url)
      );
    }

    /* =================================================
       ADMIN KYC VIEW
    ================================================= */

    if (
      method === "GET" &&
      (
        path.startsWith(
          "/api/admin/kyc/"
        ) ||
        path.startsWith(
          "/api/admin/kyc-submissions/"
        )
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      const id =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await viewKyc(id)
      );
    }

    /* =================================================
       ADMIN KYC REVIEW
    ================================================= */

    if (
      (
        method === "POST" ||
        method === "PATCH" ||
        method === "PUT"
      ) &&
      (
        path.startsWith(
          "/api/admin/kyc/"
        ) ||
        path.startsWith(
          "/api/admin/kyc-submissions/"
        )
      )
    ) {
      const id =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await reviewKyc(
          request,
          id,
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       ADMIN INVESTMENTS
    ================================================= */

    if (
      method === "GET" &&
      path === "/api/admin/investments"
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      return writeWebResponse(
        res,
        await adminInvestments(url)
      );
    }

    /* =================================================
       ADMIN TRANSACTIONS
    ================================================= */

    if (
      method === "GET" &&
      path === "/api/admin/transactions"
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      return writeWebResponse(
        res,
        await adminTransactions(url)
      );
    }

    /* =================================================
       ADMIN PENDING REQUESTS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/requests" ||
        path === "/api/admin/pending-requests"
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      return writeWebResponse(
        res,
        await adminRequests(url)
      );
    }

    /* =================================================
       ADMIN PROCESS REQUEST
    ================================================= */

    if (
      (
        method === "POST" ||
        method === "PATCH" ||
        method === "PUT"
      ) &&
      (
        path.startsWith(
          "/api/admin/requests/"
        ) ||
        path.startsWith(
          "/api/admin/pending-requests/"
        )
      )
    ) {
      const id =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await processRequest(
          request,
          id,
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       ADMIN CHAT CONVERSATIONS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/chat" ||
        path === "/api/admin/conversations"
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(auth.status, auth.error)
        );
      }

      const conversationId =
        url.searchParams.get(
          "conversation_id"
        ) ||
        url.searchParams.get(
          "conversationId"
        );

      if (conversationId) {
        return writeWebResponse(
          res,
          await adminMessages(
            conversationId
          )
        );
      }

      return writeWebResponse(
        res,
        await adminConversations()
      );
    }

    /* =================================================
       ADMIN CHAT MESSAGE VIEW
    ================================================= */

    if (
      method === "GET" &&
      (
        path.startsWith(
          "/api/admin/chat/"
        ) ||
        path.startsWith(
          "/api/admin/conversations/"
        )
      )
    ) {
      const conversationId =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await adminMessages(
          conversationId
        )
      );
    }

    /* =================================================
       ADMIN SEND CHAT MESSAGE
    ================================================= */

    if (
      method === "POST" &&
      (
        path.startsWith(
          "/api/admin/chat/"
        ) ||
        path.startsWith(
          "/api/admin/conversations/"
        )
      )
    ) {
      const conversationId =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await adminSendMessage(
          request,
          conversationId,
          await jsonBody(request)
        )
      );
    }

    /* =================================================
       UNKNOWN ROUTE
    ================================================= */

    return writeWebResponse(
      res,
      bad(
        404,
        "API route not found.",
        {
          path,
          method
        }
      )
    );

  } catch (error) {
    console.error(
      "CoinForest API error:",
      error
    );

    if (res.headersSent) {
      res.end();
      return;
    }

    return writeWebResponse(
      res,
      response(500, {
        success: false,
        error:
          error?.message ||
          "Internal server error."
      })
    );
  }
          }
