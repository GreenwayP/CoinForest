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
  return String(path || "")
    .split("/")
    .filter(Boolean);
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
    String(
      user.first_name || "Customer"
    ).trim();

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
    return bad(
      400,
      "Email and password are required."
    );
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
    console.error(
      "Verification email error:",
      error
    );

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
    return bad(
      400,
      "Email and password are required."
    );
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
    return bad(
      401,
      "Invalid email or password."
    );
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

  if (
    !verifyPassword(
      password,
      user.password_hash
    )
  ) {
    const attempts =
      Number(user.failed_login_attempts || 0) + 1;

    if (attempts >= 5) {
      await sql`
        UPDATE auth_credentials
        SET
          failed_login_attempts = 0,
          locked_until =
            NOW() + INTERVAL '15 minutes',
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

    return bad(
      401,
      "Invalid email or password."
    );
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
    String(auth.user.role_name || "")
      .toLowerCase();

  if (
    role !== "admin" &&
    role !== "administrator"
  ) {
    return {
      ok: false,
      status: 403,
      error:
        "Administrator access required."
    };
  }

  return auth;
}

/* =====================================================
   CURRENT USER
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
      email_verified_at:
        user.email_verified_at
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
    console.error(
      "Health database error:",
      error
    );

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

    sql`
      SELECT COUNT(*)::int AS count
      FROM pending_requests
      WHERE LOWER(COALESCE(status, 'pending'))
        = 'pending'
    `
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
   ADMIN CUSTOMERS
===================================================== */

async function adminCustomers(url) {
  const search =
    String(
      url.searchParams.get("search") || ""
    ).trim();

  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  const offset =
    Math.max(
      Number(
        url.searchParams.get("offset") || 0
      ),
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

  return ok({
    customers: rows
  });
}

/* =====================================================
   CUSTOMER VIEW
   RETURNS CUSTOMER + WALLETS + LEDGER
===================================================== */

async function adminCustomer(id) {
  if (!id) {
    return bad(
      400,
      "Customer ID is required."
    );
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
    return bad(
      404,
      "Customer not found."
    );
  }

  const customer = result[0];

  let wallets = [];
  let ledger = [];

  /*
   * New/canonical structure:
   * one wallet row per wallet_type.
   */
  try {
    wallets = await sql`
      SELECT *
      FROM wallets
      WHERE user_id = ${id}
      ORDER BY created_at ASC
    `;
  } catch (error) {
    console.warn(
      "Customer wallet lookup failed:",
      error?.message
    );
  }

  try {
    ledger = await sql`
      SELECT *
      FROM wallet_ledger
      WHERE user_id = ${id}
      ORDER BY created_at DESC
      LIMIT 200
    `;
  } catch (error) {
    console.warn(
      "Customer wallet ledger unavailable:",
      error?.message
    );
  }

  /*
   * If wallet_ledger does not exist, still return
   * an empty ledger rather than breaking Customer View.
   */

  return ok({
    customer,
    wallets,
    ledger
  });
}

/* =====================================================
   ADMIN CUSTOMER STATUS / APPROVAL
===================================================== */

async function updateCustomerStatus(
  request,
  id,
  body,
  forcedStatus = null
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  if (!id) {
    return bad(
      400,
      "Customer ID is required."
    );
  }

  let status =
    forcedStatus ||
    body.status ||
    body.action ||
    body.decision ||
    "";

  status =
    String(status)
      .trim()
      .toLowerCase();

  const aliases = {
    approve: "active",
    approved: "active",
    activate: "active",
    active: "active",

    suspend: "suspended",
    suspended: "suspended",

    decline: "declined",
    declined: "declined",

    reject: "declined",
    rejected: "declined",

    disable: "disabled",
    disabled: "disabled",

    freeze: "frozen",
    frozen: "frozen"
  };

  status =
    aliases[status] || status;

  const allowed = [
    "active",
    "suspended",
    "declined",
    "disabled",
    "frozen",
    "pending"
  ];

  if (!allowed.includes(status)) {
    return bad(
      400,
      "Invalid customer status."
    );
  }

  const existing = await sql`
    SELECT
      p.id,
      p.status,
      p.email,
      p.first_name,
      p.last_name,
      p.username
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE
      p.id = ${id}
      AND LOWER(COALESCE(r.name, 'user'))
        NOT IN ('admin', 'administrator')
    LIMIT 1
  `;

  if (!existing.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  const updated = await sql`
    UPDATE profiles
    SET
      status = ${status},
      updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `;

  return ok({
    message:
      `Customer status changed to ${status}.`,
    customer: updated[0]
  });
}

/* =====================================================
   ADMIN WALLETS
   SUPPORTS BOTH:
   1. wallet_type + balance rows
   2. main_balance + profit_balance row
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
      p.email
    FROM wallets w
    INNER JOIN profiles p
      ON p.id = w.user_id
    WHERE
      ${search} = ''
      OR LOWER(COALESCE(p.username, ''))
        LIKE LOWER(${"%" + search + "%"})
      OR LOWER(COALESCE(p.email, ''))
        LIKE LOWER(${"%" + search + "%"})
    ORDER BY w.created_at DESC
    LIMIT ${limit}
  `;

  return ok({
    wallets: rows
  });
}

async function adminWallet(userId) {
  if (!userId) {
    return bad(
      400,
      "User ID is required."
    );
  }

  const customer = await sql`
    SELECT
      p.id,
      p.first_name,
      p.last_name,
      p.username,
      p.email,
      p.status,
      p.kyc_status
    FROM profiles p
    WHERE p.id = ${userId}
    LIMIT 1
  `;

  if (!customer.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  let wallets = [];

  try {
    wallets = await sql`
      SELECT
        w.*,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM wallets w
      INNER JOIN profiles p
        ON p.id = w.user_id
      WHERE w.user_id = ${userId}
      ORDER BY w.created_at ASC
    `;
  } catch (error) {
    console.error(
      "Admin wallet query error:",
      error
    );

    return bad(
      500,
      "Unable to load customer wallet.",
      {
        detail:
          error?.message || "Wallet query failed."
      }
    );
  }

  let ledger = [];

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

  return ok({
    customer: customer[0],
    wallets,
    ledger
  });
}

/* =====================================================
   FIND WALLET
===================================================== */

async function findWallet(
  userId,
  walletType
) {
  /*
   * First try canonical structure:
   *
   * user_id
   * wallet_type
   * balance
   */

  try {
    const rows = await sql`
      SELECT *
      FROM wallets
      WHERE
        user_id = ${userId}
        AND LOWER(COALESCE(wallet_type, ''))
          = ${walletType}
      LIMIT 1
    `;

    if (rows.length) {
      return {
        mode: "wallet_type",
        row: rows[0]
      };
    }
  } catch (error) {
    /*
     * If wallet_type does not exist,
     * try the legacy structure below.
     */
  }

  /*
   * Legacy structure:
   *
   * one row containing
   * main_balance / profit_balance
   */

  try {
    const rows = await sql`
      SELECT *
      FROM wallets
      WHERE user_id = ${userId}
      LIMIT 1
    `;

    if (rows.length) {
      return {
        mode: "legacy",
        row: rows[0]
      };
    }
  } catch (error) {
    return null;
  }

  return null;
}

/* =====================================================
   ADMIN WALLET ADJUSTMENT
===================================================== */

async function adjustWallet(
  request,
  body
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const userId =
    String(body.user_id || "").trim();

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
        "Administrator balance adjustment"
    ).trim();

  if (!userId) {
    return bad(
      400,
      "User ID is required."
    );
  }

  if (
    !Number.isFinite(amount) ||
    amount === 0
  ) {
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

  const customer = await sql`
    SELECT id
    FROM profiles
    WHERE id = ${userId}
    LIMIT 1
  `;

  if (!customer.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  const found =
    await findWallet(
      userId,
      walletType
    );

  if (!found) {
    return bad(
      404,
      "Customer wallet not found."
    );
  }

  let current = 0;
  let next = 0;
  let updated = [];

  /*
   * CANONICAL:
   * wallet_type + balance
   */
  if (
    found.mode === "wallet_type"
  ) {
    current =
      numberValue(
        found.row.balance,
        0
      );

    next =
      current + amount;

    if (next < 0) {
      return bad(
        400,
        "Insufficient wallet balance."
      );
    }

    updated = await sql`
      UPDATE wallets
      SET
        balance = ${next},
        updated_at = NOW()
      WHERE
        id = ${found.row.id}
      RETURNING *
    `;
  }

  /*
   * LEGACY:
   * main_balance + profit_balance
   */
  else {
    const column =
      walletType === "profit"
        ? "profit_balance"
        : "main_balance";

    current =
      numberValue(
        found.row[column],
        0
      );

    next =
      current + amount;

    if (next < 0) {
      return bad(
        400,
        "Insufficient wallet balance."
      );
    }

    if (walletType === "profit") {
      updated = await sql`
        UPDATE wallets
        SET
          profit_balance = ${next},
          updated_at = NOW()
        WHERE user_id = ${userId}
        RETURNING *
      `;
    } else {
      updated = await sql`
        UPDATE wallets
        SET
          main_balance = ${next},
          updated_at = NOW()
        WHERE user_id = ${userId}
        RETURNING *
      `;
    }
  }

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

  return ok({
    message:
      "Wallet balance updated successfully.",
    wallet: updated[0],
    wallet_type: walletType,
    balance_before: current,
    balance_after: next
  });
}

/* =====================================================
   ADMIN KYC
   IMPORTANT:
   ALSO SHOWS PROFILES WITH PENDING KYC
   EVEN WHEN kyc_submissions IS EMPTY.
===================================================== */

async function adminKyc(url) {
  const requestedStatus =
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

  let submissions = [];

  /*
   * Existing KYC submission records.
   */
  try {
    if (requestedStatus) {
      submissions = await sql`
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
        WHERE
          LOWER(COALESCE(k.status, 'pending'))
            = ${requestedStatus}
        ORDER BY k.created_at DESC
        LIMIT ${limit}
      `;
    } else {
      submissions = await sql`
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
  } catch (error) {
    console.warn(
      "kyc_submissions unavailable:",
      error?.message
    );
  }

  /*
   * Also get profile-level KYC accounts.
   * This fixes the situation where Dashboard says
   * pending KYC exists but the KYC page says zero.
   */
  let profiles = [];

  try {
    if (requestedStatus) {
      profiles = await sql`
        SELECT
          p.id AS user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          p.status AS account_status,
          p.kyc_status,
          p.created_at,
          p.updated_at
        FROM profiles p
        LEFT JOIN roles r
          ON r.id = p.role_id
        WHERE
          LOWER(COALESCE(r.name, 'user'))
            NOT IN ('admin', 'administrator')
          AND LOWER(
            COALESCE(p.kyc_status, 'pending')
          ) = ${requestedStatus}
        ORDER BY p.created_at DESC
        LIMIT ${limit}
      `;
    } else {
      profiles = await sql`
        SELECT
          p.id AS user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          p.status AS account_status,
          p.kyc_status,
          p.created_at,
          p.updated_at
        FROM profiles p
        LEFT JOIN roles r
          ON r.id = p.role_id
        WHERE
          LOWER(COALESCE(r.name, 'user'))
            NOT IN ('admin', 'administrator')
          AND LOWER(
            COALESCE(p.kyc_status, 'pending')
          ) IN (
            'pending',
            'submitted',
            'under_review',
            'approved',
            'rejected'
          )
        ORDER BY p.created_at DESC
        LIMIT ${limit}
      `;
    }
  } catch (error) {
    console.warn(
      "Profile KYC query failed:",
      error?.message
    );
  }

  /*
   * Merge both sources without duplicating
   * the same customer.
   */
  const merged = new Map();

  for (const row of submissions) {
    const userId =
      row.user_id || row.id;

    if (!userId) continue;

    merged.set(
      String(userId),
      {
        ...row,
        source: "kyc_submission"
      }
    );
  }

  for (const row of profiles) {
    const userId = row.user_id;

    if (!userId) continue;

    const key = String(userId);

    if (!merged.has(key)) {
      merged.set(
        key,
        {
          ...row,
          id: row.user_id,
          status:
            row.kyc_status || "pending",
          source: "profile"
        }
      );
    }
  }

  let result = Array.from(
    merged.values()
  );

  if (requestedStatus) {
    result = result.filter(
      item =>
        String(
          item.status ||
            item.kyc_status ||
            "pending"
        )
          .toLowerCase() ===
        requestedStatus
    );
  }

  result =
    result.slice(0, limit);

  return ok({
    submissions: result,
    kyc: result,
    count: result.length
  });
}

/* =====================================================
   REVIEW KYC
===================================================== */

async function reviewKyc(
  request,
  id,
  body
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
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
    decision !== "rejected"
  ) {
    return bad(
      400,
      "KYC decision must be approved or rejected."
    );
  }

  /*
   * First try a real KYC submission.
   */
  let submission = [];

  try {
    submission = await sql`
      SELECT *
      FROM kyc_submissions
      WHERE id = ${id}
      LIMIT 1
    `;
  } catch {}

  let userId = null;
  let updatedSubmission = null;

  if (submission.length) {
    userId = submission[0].user_id;

    try {
      const updated =
        await sql`
          UPDATE kyc_submissions
          SET
            status = ${decision},
            reviewed_by = ${admin.user.id},
            reviewed_at = NOW(),
            updated_at = NOW()
          WHERE id = ${id}
          RETURNING *
        `;

      updatedSubmission =
        updated[0] || null;
    } catch {}
  } else {
    /*
     * If the KYC page is displaying a profile-level
     * pending account, the supplied ID is the user ID.
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

    userId = profile[0].id;
  }

  await sql`
    UPDATE profiles
    SET
      kyc_status = ${decision},
      updated_at = NOW()
    WHERE id = ${userId}
  `;

  return ok({
    message:
      `KYC ${decision} successfully.`,
    submission:
      updatedSubmission,
    user_id: userId,
    kyc_status: decision
  });
}

/* =====================================================
   ADMIN INVESTMENTS
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
   ADMIN TRANSACTIONS
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
   ADMIN PENDING REQUESTS
===================================================== */

async function adminRequests(url) {
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
    return bad(
      admin.status,
      admin.error
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
    decision !== "rejected"
  ) {
    return bad(
      400,
      "Decision must be approved or rejected."
    );
  }

  const rows = await sql`
    SELECT *
    FROM pending_requests
    WHERE id = ${id}
    LIMIT 1
  `;

  if (!rows.length) {
    return bad(
      404,
      "Request not found."
    );
  }

  const item = rows[0];

  const updated = await sql`
    UPDATE pending_requests
    SET
      status = ${decision},
      reviewed_by = ${admin.user.id},
      reviewed_at = NOW(),
      updated_at = NOW()
    WHERE id = ${id}
    RETURNING *
  `;

  if (
    decision === "approved" &&
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
        const found =
          await findWallet(
            item.user_id,
            "main"
          );

        if (found) {
          if (
            found.mode === "wallet_type"
          ) {
            const oldBalance =
              numberValue(
                found.row.balance,
                0
              );

            const newBalance =
              oldBalance + amount;

            await sql`
              UPDATE wallets
              SET
                balance = ${newBalance},
                updated_at = NOW()
              WHERE id =
                ${found.row.id}
            `;
          } else {
            const oldBalance =
              numberValue(
                found.row.main_balance,
                0
              );

            const newBalance =
              oldBalance + amount;

            await sql`
              UPDATE wallets
              SET
                main_balance = ${newBalance},
                updated_at = NOW()
              WHERE user_id =
                ${item.user_id}
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
      `Request ${decision} successfully.`,
    request: updated[0]
  });
}

/* =====================================================
   ADMIN CHAT CONVERSATIONS
===================================================== */

async function adminConversations() {
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
    conversations: rows
  });
}

async function adminMessages(conversationId) {
  if (!conversationId) {
    return bad(
      400,
      "Conversation ID is required."
    );
  }

  try {
    const rows = await sql`
      SELECT *
      FROM chat_messages
      WHERE conversation_id =
        ${conversationId}
      ORDER BY created_at ASC
    `;

    return ok({
      messages: rows
    });
  } catch (error) {
    console.error(
      "Admin chat message query failed:",
      error
    );

    return bad(
      500,
      "Unable to load customer chat messages.",
      {
        detail:
          error?.message ||
          "chat_messages query failed."
      }
    );
  }
}

async function adminSendMessage(
  request,
  conversationId,
  body
) {
  const admin = await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
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

  const conversation =
    await sql`
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

  const id =
    crypto.randomUUID();

  let rows;

  try {
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
  } catch (error) {
    console.error(
      "Admin chat insert failed:",
      error
    );

    return bad(
      500,
      "Unable to send customer chat message.",
      {
        detail:
          error?.message ||
          "chat_messages insert failed."
      }
    );
  }

  try {
    await sql`
      UPDATE chat_conversations
      SET
        updated_at = NOW()
      WHERE id = ${conversationId}
    `;
  } catch {}

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
    activity:
      activities.slice(0, 30)
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
    return bad(
      admin.status,
      admin.error
    );
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
        COALESCE(
          ${firstName},
          first_name
        ),
      last_name =
        COALESCE(
          ${lastName},
          last_name
        ),
      username =
        COALESCE(
          ${username},
          username
        ),
      status =
        COALESCE(
          ${status},
          status
        ),
      kyc_status =
        COALESCE(
          ${kycStatus},
          kyc_status
        ),
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
    request.headers.get(
      "x-admin-reset-key"
    );

  const configuredKey =
    process.env.ADMIN_RESET_KEY;

  if (
    !configuredKey ||
    resetKey !== configuredKey
  ) {
    return bad(
      403,
      "Unauthorized."
    );
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
      AND t.token_type =
        'email_verification'
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
      if (
        typeof req.body === "string"
      ) {
        body = req.body;
      } else if (
        Buffer.isBuffer(req.body)
      ) {
        body = req.body;
      } else {
        body =
          JSON.stringify(req.body);

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
      method:
        req.method || "GET",
      headers:
        requestHeaders,
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
       REGISTER
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
       LOGIN
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
          bad(
            auth.status,
            auth.error
          )
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
          bad(
            auth.status,
            auth.error
          )
        );
      }

      return writeWebResponse(
        res,
        await adminActivity()
      );
    }

    /* =================================================
       ADMIN CUSTOMERS LIST / VIEW
    ================================================= */

    if (
      method === "GET" &&
      path === "/api/admin/customers"
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(
            auth.status,
            auth.error
          )
        );
      }

      const id =
        url.searchParams.get("id") ||
        url.searchParams.get("user_id");

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
       ADMIN CUSTOMER VIEW ALIASES
       Supports frontends using:
       /customers/:id
       /customer/:id
       /customer?id=
    ================================================= */

    if (
      method === "GET" &&
      (
        path.startsWith(
          "/api/admin/customers/"
        ) ||
        path.startsWith(
          "/api/admin/customer/"
        )
      )
    ) {
      const id =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await adminCustomer(id)
      );
    }

    if (
      method === "GET" &&
      path === "/api/admin/customer"
    ) {
      const id =
        url.searchParams.get("id") ||
        url.searchParams.get("user_id");

      return writeWebResponse(
        res,
        await adminCustomer(id)
      );
    }

    /* =================================================
       ADMIN CUSTOMER STATUS / APPROVAL
    ================================================= */

    if (
      (
        method === "PUT" ||
        method === "PATCH" ||
        method === "POST"
      ) &&
      (
        path.startsWith(
          "/api/admin/customers/"
        ) ||
        path.startsWith(
          "/api/admin/customer/"
        )
      )
    ) {
      const index =
        parts.findIndex(
          item =>
            item === "customers" ||
            item === "customer"
        );

      const id =
        index >= 0
          ? parts[index + 1]
          : null;

      const action =
        index >= 0
          ? parts[index + 2]
          : null;

      const body =
        await jsonBody(request);

      /*
       * /customers/:id/status
       * /customers/:id/approve
       * /customers/:id/suspend
       * /customers/:id/decline
       */
      if (
        action === "status" ||
        action === "approve" ||
        action === "approved" ||
        action === "activate" ||
        action === "suspend" ||
        action === "suspended" ||
        action === "decline" ||
        action === "declined" ||
        action === "reject" ||
        action === "rejected" ||
        action === "disable" ||
        action === "disabled" ||
        action === "freeze" ||
        action === "frozen"
      ) {
        return writeWebResponse(
          res,
          await updateCustomerStatus(
            request,
            id,
            body,
            action === "status"
              ? null
              : action
          )
        );
      }

      return writeWebResponse(
        res,
        await updateCustomer(
          request,
          id,
          body
        )
      );
    }

    /* =================================================
       ADMIN WALLET LIST / CUSTOMER WALLET
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
          bad(
            auth.status,
            auth.error
          )
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
       CUSTOMER WALLET VIEW ALIASES
    ================================================= */

    if (
      method === "GET" &&
      (
        path.startsWith(
          "/api/admin/wallets/"
        ) ||
        path.startsWith(
          "/api/admin/wallet/"
        )
      )
    ) {
      const id =
        parts[parts.length - 1];

      return writeWebResponse(
        res,
        await adminWallet(id)
      );
    }

    /* =================================================
       ADMIN WALLET ADJUST
    ================================================= */

    if (
      (
        method === "POST" ||
        method === "PUT" ||
        method === "PATCH"
      ) &&
      (
        path ===
          "/api/admin/wallets/adjust" ||
        path ===
          "/api/admin/wallet/adjust" ||
        path ===
          "/api/admin/wallet-adjust"
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
          bad(
            auth.status,
            auth.error
          )
        );
      }

      return writeWebResponse(
        res,
        await adminKyc(url)
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
          bad(
            auth.status,
            auth.error
          )
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
          bad(
            auth.status,
            auth.error
          )
        );
      }

      return writeWebResponse(
        res,
        await adminTransactions(url)
      );
    }

    /* =================================================
       ADMIN REQUESTS
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/admin/requests" ||
        path ===
          "/api/admin/pending-requests"
      )
    ) {
      const auth =
        await requireAdmin(request);

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(
            auth.status,
            auth.error
          )
        );
      }

      return writeWebResponse(
        res,
        await adminRequests(url)
      );
    }

    /* =================================================
       PROCESS REQUEST
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
       ADMIN CHAT LIST
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
          bad(
            auth.status,
            auth.error
          )
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
       ADMIN CHAT MESSAGES
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
