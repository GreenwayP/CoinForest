/* =====================================================
   COINFOREST API — COMPLETE INDEX.JS
   ADMIN CHAT / TRANSACTIONS / ACTIVITIES FIX
   Existing authentication, KYC, chat, requests,
   investments and customer functions preserved.
===================================================== */

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

async function sendVerificationEmail(
  request,
  user
) {
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
    subject:
      "Confirm your CoinForest account",
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
  const email =
    normalizeEmail(body.email);

  const password =
    String(body.password || "");

  const firstName =
    String(body.first_name || "").trim();

  const lastName =
    String(body.last_name || "").trim();

  const username =
    String(body.username || "").trim();

  if (!email || !password) {
    return bad(
      400,
      "Email and password are required."
    );
  }

  if (!firstName) {
    return bad(
      400,
      "First name is required."
    );
  }

  if (!lastName) {
    return bad(
      400,
      "Last name is required."
    );
  }

  if (!username) {
    return bad(
      400,
      "Username is required."
    );
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
    WHERE LOWER(username) =
      LOWER(${username})
    LIMIT 1
  `;

  if (existingUsername.length) {
    return bad(
      409,
      "That username is already in use."
    );
  }

  const id = crypto.randomUUID();

  const passwordHash =
    hashPassword(password);

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

  await ensureUserWallets(id);

  const user = {
    id,
    email,
    first_name: firstName,
    last_name: lastName,
    username
  };

  try {
    await sendVerificationEmail(
      request,
      user
    );
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
   WALLET FOUNDATION
===================================================== */

async function ensureUserWallets(userId) {
  if (!userId) return;

  try {
    await sql`
      INSERT INTO wallets (
        id,
        user_id,
        wallet_type,
        currency,
        balance,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${userId},
        'main',
        'USD',
        0,
        'active',
        NOW(),
        NOW()
      )
      ON CONFLICT DO NOTHING
    `;
  } catch (error) {
    try {
      await sql`
        INSERT INTO wallets (
          id,
          user_id,
          main_balance,
          profit_balance,
          currency,
          status,
          created_at,
          updated_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${userId},
          0,
          0,
          'USD',
          'active',
          NOW(),
          NOW()
        )
        ON CONFLICT DO NOTHING
      `;
    } catch (legacyError) {
      console.warn(
        "Main wallet creation warning:",
        legacyError?.message ||
          error?.message
      );
    }
  }

  try {
    await sql`
      INSERT INTO wallets (
        id,
        user_id,
        wallet_type,
        currency,
        balance,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${userId},
        'profit',
        'USD',
        0,
        'active',
        NOW(),
        NOW()
      )
      ON CONFLICT DO NOTHING
    `;
  } catch (error) {
    console.warn(
      "Profit wallet creation compatibility warning:",
      error?.message
    );
  }
}

async function ensureAllCustomerWallets() {
  const customers = await sql`
    SELECT
      p.id
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE LOWER(COALESCE(r.name, 'user'))
      NOT IN ('admin', 'administrator')
  `;

  for (const customer of customers) {
    try {
      await ensureUserWallets(
        customer.id
      );
    } catch (error) {
      console.warn(
        "Unable to ensure wallet for:",
        customer.id,
        error?.message
      );
    }
  }

  return customers.length;
}

/* =====================================================
   LOGIN
===================================================== */

async function login(body) {
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
    new Date(user.locked_until) >
      new Date()
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
      Number(
        user.failed_login_attempts || 0
      ) + 1;

    if (attempts >= 5) {
      await sql`
        UPDATE auth_credentials
        SET
          failed_login_attempts = 0,
          locked_until =
            NOW() +
            INTERVAL '15 minutes',
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
      email_verified:
        !!user.email_verified_at
    }
  });
}

/* =====================================================
   AUTHENTICATE SESSION
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

  const tokenHash =
    hashToken(token);

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
      s.session_token_hash =
        ${tokenHash}
      AND s.status = 'active'
      AND s.expires_at > NOW()
    LIMIT 1
  `;

  if (!result.length) {
    return {
      ok: false,
      status: 401,
      error:
        "Invalid or expired session."
    };
  }

  await sql`
    UPDATE user_sessions
    SET
      last_activity_at = NOW(),
      updated_at = NOW()
    WHERE
      session_token_hash =
        ${tokenHash}
      AND status = 'active'
  `;

  return {
    ok: true,
    user: result[0],
    token
  };
}

async function requireAdmin(request) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return auth;
  }

  const role =
    String(
      auth.user.role_name || ""
    ).toLowerCase();

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
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
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
        session_token_hash =
          ${hashToken(token)}
        AND status = 'active'
    `;
  }

  return ok({
    message:
      "Logged out successfully."
  });
}

/* =====================================================
   HEALTH
===================================================== */

async function health() {
  try {
    await sql`SELECT 1`;

    return ok({
      message:
        "CoinForest API is running.",
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
      customers:
        customers[0]?.count || 0,
      pending_kyc:
        pendingKyc[0]?.count || 0,
      investments:
        investments[0]?.count || 0,
      transactions:
        transactions[0]?.count || 0,
      pending_requests:
        pendingRequests[0]?.count || 0
    }
  });
}

/* ============================================type ADMIN CUSTOMERS
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

  return ok({
    customer: result[0]
  });
}

/* =====================================================
   ADMIN WALLETS
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

  await ensureAllCustomerWallets();

  const customers = await sql`
    SELECT
      p.id AS user_id,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM profiles p
    LEFT JOIN roles r
      ON r.id = p.role_id
    WHERE
      LOWER(COALESCE(r.name, 'user'))
        NOT IN ('admin', 'administrator')
      AND (
        ${search} = ''
        OR LOWER(COALESCE(p.username, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(COALESCE(p.email, ''))
          LIKE LOWER(${"%" + search + "%"})
        OR LOWER(
          COALESCE(
            p.first_name || ' ' || p.last_name,
            ''
          )
        )
          LIKE LOWER(${"%" + search + "%"})
      )
    ORDER BY p.created_at DESC
    LIMIT ${limit}
  `;

  const result = [];

  for (const customer of customers) {
    let walletRows = [];

    try {
      walletRows = await sql`
        SELECT *
        FROM wallets
        WHERE user_id = ${customer.user_id}
        ORDER BY created_at ASC
      `;
    } catch (error) {
      console.warn(
        "Wallet query warning:",
        error?.message
      );
    }

    let main = null;
    let profit = null;

    for (const wallet of walletRows) {
      const type =
        String(
          wallet.wallet_type || ""
        ).toLowerCase();

      if (type === "main") {
        main = wallet;
      }

      if (type === "profit") {
        profit = wallet;
      }
    }

    if (!main && walletRows.length) {
      const legacy = walletRows[0];

      if (
        legacy.main_balance !== undefined ||
        legacy.profit_balance !== undefined
      ) {
        main = legacy;
      }
    }

    result.push({
      id:
        main?.id ||
        profit?.id ||
        customer.user_id,

      user_id:
        customer.user_id,

      first_name:
        customer.first_name,

      last_name:
        customer.last_name,

      username:
        customer.username,

      email:
        customer.email,

      wallet_type:
        "combined",

      currency:
        main?.currency ||
        profit?.currency ||
        "USD",

      status:
        main?.status ||
        profit?.status ||
        "active",

      main_wallet_id:
        main?.id || null,

      profit_wallet_id:
        profit?.id || null,

      main_balance:
        main?.balance !== undefined
          ? numberValue(main.balance)
          : numberValue(
              main?.main_balance,
              0
            ),

      profit_balance:
        profit?.balance !== undefined
          ? numberValue(profit.balance)
          : numberValue(
              main?.profit_balance,
              0
            ),

      created_at:
        main?.created_at ||
        profit?.created_at ||
        null,

      updated_at:
        main?.updated_at ||
        profit?.updated_at ||
        null
    });
  }

  return ok({
    wallets: result
  });
}

/* =====================================================
   ADMIN SINGLE CUSTOMER WALLET
===================================================== */

async function adminWallet(userId) {
  if (!userId) {
    return bad(
      400,
      "User ID is required."
    );
  }

  await ensureUserWallets(userId);

  const profile = await sql`
    SELECT
      p.id,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM profiles p
    WHERE p.id = ${userId}
    LIMIT 1
  `;

  if (!profile.length) {
    return bad(
      404,
      "Customer not found."
    );
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
    return bad(
      500,
      "Unable to load customer wallet.",
      {
        detail:
          error?.message
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
    customer:
      profile[0],
    wallets,
    ledger
  });
}

/* =====================================================
   ADMIN WALLET ADJUSTMENT
===================================================== */

async function adjustWallet(
  request,
  body
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const userId =
    String(
      body.user_id || ""
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

  await ensureUserWallets(userId);

  let walletRows = [];

  try {
    walletRows = await sql`
      SELECT *
      FROM wallets
      WHERE user_id = ${userId}
        AND wallet_type = ${walletType}
      LIMIT 1
    `;
  } catch {
    walletRows = [];
  }

  if (walletRows.length) {
    const wallet =
      walletRows[0];

    const current =
      numberValue(
        wallet.balance,
        0
      );

    const next =
      current + amount;

    if (next < 0) {
      return bad(
        400,
        "Insufficient wallet balance."
      );
    }

    const updated =
      await sql`
        UPDATE wallets
        SET
          balance = ${next},
          updated_at = NOW()
        WHERE id = ${wallet.id}
        RETURNING *
      `;

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

    try {
      await sql`
        INSERT INTO transactions (
          id,
          user_id,
          transaction_type,
          direction,
          amount,
          fee,
          currency,
          status,
          description,
          metadata,
          created_at,
          updated_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${userId},
          'system',
          ${amount >= 0 ? "credit" : "debit"},
          ${Math.abs(amount)},
          0,
          'USD',
          'completed',
          ${reason},
          ${JSON.stringify({
            source:
              "admin_wallet_adjustment",
            wallet_type:
              walletType,
            admin_id:
              admin.user.id,
            adjustment:
              amount
          })},
          NOW(),
          NOW()
        )
      `;
    } catch (error) {
      try {
        await sql`
          INSERT INTO transactions (
            id,
            user_id,
            transaction_type,
            amount,
            currency,
            status,
            description,
            created_at
          )
          VALUES (
            ${crypto.randomUUID()},
            ${userId},
            'system',
            ${amount},
            'USD',
            'completed',
            ${reason},
            NOW()
          )
        `;
      } catch (legacyError) {
        console.warn(
          "Transaction record warning:",
          legacyError?.message ||
            error?.message
        );
      }
    }

    return ok({
      message:
        "Wallet balance updated successfully.",
      wallet:
        updated[0]
    });
  }

  const legacyRows = await sql`
    SELECT *
    FROM wallets
    WHERE user_id = ${userId}
    LIMIT 1
  `;

  if (!legacyRows.length) {
    return bad(
      404,
      "Customer wallet not found."
    );
  }

  const wallet =
    legacyRows[0];

  const column =
    walletType === "profit"
      ? "profit_balance"
      : "main_balance";

  if (
    wallet[column] === undefined
  ) {
    return bad(
      500,
      "Wallet structure is not compatible with the configured wallet system."
    );
  }

  const current =
    numberValue(
      wallet[column],
      0
    );

  const next =
    current + amount;

  if (next < 0) {
    return bad(
      400,
      "Insufficient wallet balance."
    );
  }

  let updated;

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
      "Legacy wallet ledger warning:",
      error?.message
    );
  }

  try {
    await sql`
      INSERT INTO transactions (
        id,
        user_id,
        transaction_type,
        direction,
        amount,
        fee,
        currency,
        status,
        description,
        metadata,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${userId},
        'system',
        ${amount >= 0 ? "credit" : "debit"},
        ${Math.abs(amount)},
        0,
        'USD',
        'completed',
        ${reason},
        ${JSON.stringify({
          source:
            "admin_wallet_adjustment",
          wallet_type:
            walletType,
          admin_id:
            admin.user.id,
          adjustment:
            amount
        })},
        NOW(),
        NOW()
      )
    `;
  } catch (error) {
    try {
      await sql`
        INSERT INTO transactions (
          id,
          user_id,
          transaction_type,
          amount,
          currency,
          status,
          description,
          created_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${userId},
          'system',
          ${amount},
          'USD',
          'completed',
          ${reason},
          NOW()
        )
      `;
    } catch (legacyError) {
      console.warn(
        "Legacy transaction warning:",
        legacyError?.message ||
          error?.message
      );
    }
  }

  return ok({
    message:
      "Wallet balance updated successfully.",
    wallet:
      updated[0]
  });
}

/* =====================================================
   ADMIN KYC
===================================================== */

async function adminKyc(url) {
  const status =
    String(
      url.searchParams.get("status") || ""
    ).trim().toLowerCase();

  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      100
    );

  let rows = [];

  try {
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
  } catch (error) {
    const profileRows =
      await sql`
        SELECT
          p.id AS id,
          p.id AS user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          p.status AS account_status,
          COALESCE(
            p.kyc_status,
            'pending'
          ) AS status,
          p.kyc_status,
          p.created_at,
          p.updated_at
        FROM profiles p
        LEFT JOIN roles r
          ON r.id = p.role_id
        WHERE LOWER(COALESCE(r.name, 'user'))
          NOT IN ('admin', 'administrator')
          AND (
            ${status} = ''
            OR LOWER(
              COALESCE(
                p.kyc_status,
                'pending'
              )
            ) = ${status}
          )
        ORDER BY p.created_at DESC
        LIMIT ${limit}
      `;

    rows = profileRows;
  }

  if (!rows.length) {
    rows = await sql`
      SELECT
        p.id AS id,
        p.id AS user_id,
        p.first_name,
        p.last_name,
        p.username,
        p.email,
        p.status AS account_status,
        COALESCE(
          p.kyc_status,
          'pending'
        ) AS status,
        p.kyc_status,
        p.created_at,
        p.updated_at
      FROM profiles p
      LEFT JOIN roles r
        ON r.id = p.role_id
      WHERE LOWER(COALESCE(r.name, 'user'))
        NOT IN ('admin', 'administrator')
        AND (
          ${status} = ''
          OR LOWER(
            COALESCE(
              p.kyc_status,
              'pending'
            )
          ) = ${status}
        )
      ORDER BY p.created_at DESC
      LIMIT ${limit}
    `;
  }

  return ok({
    submissions: rows
  });
}

async function reviewKyc(
  request,
  id,
  body
) {
  const admin =
    await requireAdmin(request);

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

  let submission = [];

  try {
    submission =
      await sql`
        SELECT *
        FROM kyc_submissions
        WHERE id = ${id}
        LIMIT 1
      `;
  } catch {
    submission = [];
  }

  if (!submission.length) {
    const profile =
      await sql`
        SELECT id
        FROM profiles
        WHERE id = ${id}
        LIMIT 1
      `;

    if (!profile.length) {
      return bad(
        404,
        "KYC/customer record not found."
      );
    }

    await sql`
      UPDATE profiles
      SET
        kyc_status = ${decision},
        updated_at = NOW()
      WHERE id = ${id}
    `;

    return ok({
      message:
        `KYC ${decision} successfully.`,
      submission: {
        id,
        user_id: id,
        status: decision
      }
    });
  }

  const userId =
    submission[0].user_id;

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
      updated[0]
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
   ADMIN TRANSACTIONS — FIXED
===================================================== */

/*
 * The old version used INNER JOIN profiles.
 *
 * That could make valid transactions disappear when
 * the corresponding profile relationship was missing,
 * malformed, or when an old transaction referenced a
 * customer record that was later changed.
 *
 * This version:
 *
 * 1. Uses LEFT JOIN.
 * 2. Keeps the transaction even if profile information
 *    cannot be joined.
 * 3. Includes wallet ledger activity as a fallback.
 * 4. Never turns the whole endpoint into a 500 simply
 *    because an optional legacy column/table differs.
 */

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

  let rows = [];

  try {
    if (type) {
      rows = await sql`
        SELECT
          t.*,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM transactions t
        LEFT JOIN profiles p
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
        LEFT JOIN profiles p
          ON p.id = t.user_id
        ORDER BY t.created_at DESC
        LIMIT ${limit}
      `;
    }
  } catch (error) {
    console.error(
      "Primary admin transaction query failed:",
      error?.message
    );

    /*
     * Compatibility fallback for transaction schemas
     * where selecting t.* with profile fields may fail.
     */
    try {
      rows = await sql`
        SELECT
          t.id,
          t.user_id,
          t.type,
          t.direction,
          t.amount,
          t.fee,
          t.currency,
          t.status,
          t.description,
          t.created_at,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM transactions t
        LEFT JOIN profiles p
          ON p.id = t.user_id
        ORDER BY t.created_at DESC
        LIMIT ${limit}
      `;
    } catch (fallbackError) {
      console.error(
        "Transaction fallback failed:",
        fallbackError?.message
      );

      return bad(
        500,
        "Unable to load transactions.",
        {
          detail:
            fallbackError?.message ||
            error?.message
        }
      );
    }
  }

  /*
   * If transactions exist, return them normally.
   * If there are no transaction records but wallet
   * activity exists, expose the wallet ledger instead
   * so Admin is not falsely shown an empty transaction
   * history.
   */
  if (!rows.length) {
    try {
      const ledgerRows =
        await sql`
          SELECT
            wl.id,
            wl.user_id,
            wl.wallet_type,
            wl.amount,
            wl.balance_before,
            wl.balance_after,
            wl.entry_type,
            wl.description,
            wl.created_at,
            p.first_name,
            p.last_name,
            p.username,
            p.email
          FROM wallet_ledger wl
          LEFT JOIN profiles p
            ON p.id = wl.user_id
          ORDER BY wl.created_at DESC
          LIMIT ${limit}
        `;

      rows =
        ledgerRows.map(
          (item) => ({
            id: item.id,
            user_id: item.user_id,
            type:
              item.entry_type ||
              "wallet_activity",
            direction:
              numberValue(
                item.amount,
                0
              ) >= 0
                ? "credit"
                : "debit",
            amount:
              Math.abs(
                numberValue(
                  item.amount,
                  0
                )
              ),
            fee: 0,
            currency: "USD",
            status: "completed",
            description:
              item.description ||
              "Wallet activity",
            wallet_type:
            chatFoundationPromiseFoundationPromiseem.wallet_type,
            balance_before:
              item.balance_before,
            balance_after:
              item.balance_after,
            created_at:
              item.created_at,
            first_name:
              item.first_name,
            last_name:
              item.last_name,
            username:
              item.username,
            email:
              item.email,
            source:
              "wallet_ledger"
          })
        );
    } catch (error) {
      console.warn(
        "Transaction ledger fallback unavailable:",
        error?.message
      );
    }
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

  try {
    /*
     * Pending Requests are stored in two real tables:
     * 1. deposit_requests
     * 2. withdrawal_requests
     *
     * There is no pending_requests table.
     */

    const deposits = await sql`
      SELECT
        d.id,
        d.deposit_reference AS request_reference,
        d.user_id,
        d.wallet_id,
        d.amount,
        d.currency,
        d.payment_method,
        d.payment_reference,
        d.proof_url,
        d.status,
        d.submitted_at AS created_at,
        d.reviewed_at,
        d.reviewed_by,
        d.admin_notes,
        'deposit' AS type,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM deposit_requests d
      LEFT JOIN profiles p
        ON p.id = d.user_id
      WHERE LOWER(COALESCE(d.status, 'pending'))
        = ${status}
      ORDER BY d.submitted_at DESC
      LIMIT ${limit}
    `;

    const withdrawals = await sql`
      SELECT
        w.id,
        w.withdrawal_reference AS request_reference,
        w.user_id,
        w.wallet_id,
        w.amount,
        w.currency,
        w.withdrawal_method AS payment_method,
        NULL AS payment_reference,
        NULL AS proof_url,
        w.status,
        w.requested_at AS created_at,
        w.reviewed_at,
        w.reviewed_by,
        w.admin_notes,
        'withdrawal' AS type,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM withdrawal_requests w
      LEFT JOIN profiles p
        ON p.id = w.user_id
      WHERE LOWER(COALESCE(w.status, 'pending'))
        = ${status}
      ORDER BY w.requested_at DESC
      LIMIT ${limit}
    `;

    const rows = [
      ...deposits,
      ...withdrawals
    ].sort(
      (a, b) =>
        new Date(b.created_at).getTime() -
        new Date(a.created_at).getTime()
    );

    return ok({
      requests: rows.slice(0, limit)
    });

  } catch (error) {
    console.error(
      "Admin pending requests load error:",
      error
    );

    return bad(
      500,
      "Unable to load pending requests.",
      {
        detail:
          error?.message ||
          "Pending request query failed."
      }
    );
  }
}

async function processRequest(
  request,
  id,
  body
) {
  const admin =
    await requireAdmin(request);

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

  if (!id) {
    return bad(
      400,
      "Request ID is required."
    );
  }

  /*
   * The CoinForest database does NOT have a
   * pending_requests table.
   *
   * Requests are stored separately in:
   *   deposit_requests
   *   withdrawal_requests
   *
   * Find the request by ID in either table.
   */

  let requestType = null;
  let item = null;

  const depositRows = await sql`
    SELECT *
    FROM deposit_requests
    WHERE id = ${id}
    LIMIT 1
  `;

  if (depositRows.length) {
    requestType = "deposit";
    item = depositRows[0];
  } else {
    const withdrawalRows = await sql`
      SELECT *
      FROM withdrawal_requests
      WHERE id = ${id}
      LIMIT 1
    `;

    if (withdrawalRows.length) {
      requestType = "withdrawal";
      item = withdrawalRows[0];
    }
  }

  if (!item) {
    return bad(
      404,
      "Request not found."
    );
  }

  /*
   * Prevent processing the same request twice.
   */
  const currentStatus =
    String(
      item.status || "pending"
    )
      .trim()
      .toLowerCase();

  if (currentStatus !== "pending") {
    return bad(
      400,
      `Request has already been ${currentStatus}.`
    );
  }

  const amount =
    numberValue(
      item.amount,
      0
    );

  if (amount <= 0) {
    return bad(
      400,
      "Request amount must be greater than zero."
    );
  }

  /*
   * =====================================================
   * REJECT REQUEST
   * =====================================================
   *
   * Rejection changes only the request status.
   * No wallet balance is changed.
   */

  if (decision === "rejected") {

    if (requestType === "deposit") {

      const updated =
        await sql`
          UPDATE deposit_requests
          SET
            status = 'rejected',
            reviewed_by = ${admin.user.id},
            reviewed_at = NOW(),
            admin_notes =
              COALESCE(
                ${body.admin_notes || body.notes || null},
                admin_notes
              ),
            updated_at = NOW()
          WHERE id = ${id}
            AND LOWER(COALESCE(status, 'pending'))
              = 'pending'
          RETURNING *
        `;

      if (!updated.length) {
        return bad(
          400,
          "Request could not be rejected because it is no longer pending."
        );
      }

      return ok({
        message:
          "Deposit request rejected successfully.",
        request: {
          ...updated[0],
          type: "deposit"
        }
      });
    }

    const updated =
      await sql`
        UPDATE withdrawal_requests
        SET
          status = 'rejected',
          reviewed_by = ${admin.user.id},
          reviewed_at = NOW(),
          admin_notes =
            COALESCE(
              ${body.admin_notes || body.notes || null},
              admin_notes
            ),
          updated_at = NOW()
        WHERE id = ${id}
          AND LOWER(COALESCE(status, 'pending'))
            = 'pending'
        RETURNING *
      `;

    if (!updated.length) {
      return bad(
        400,
        "Request could not be rejected because it is no longer pending."
      );
    }

    return ok({
      message:
        "Withdrawal request rejected successfully.",
      request: {
        ...updated[0],
        type: "withdrawal"
      }
    });
  }

  /*
   * =====================================================
   * APPROVE DEPOSIT
   * =====================================================
   *
   * Deposit approval:
   * 1. Find/create the customer's Main Wallet.
   * 2. Credit the deposit amount.
   * 3. Create a transaction ledger entry.
   * 4. Mark the deposit approved.
   */

  if (requestType === "deposit") {

    await ensureUserWallets(
      item.user_id
    );

    const walletRows =
      await sql`
        SELECT *
        FROM wallets
        WHERE user_id = ${item.user_id}
          AND wallet_type = 'main'
          AND LOWER(COALESCE(currency, 'USD'))
            = LOWER(${item.currency || "USD"})
        LIMIT 1
      `;

    if (!walletRows.length) {
      return bad(
        500,
        "Main wallet could not be found for this customer."
      );
    }

    const wallet =
      walletRows[0];

    const oldBalance =
      numberValue(
        wallet.balance,
        0
      );

    const newBalance =
      oldBalance + amount;

    /*
     * Credit the customer's Main Wallet.
     */
    await sql`
      UPDATE wallets
      SET
        balance = ${newBalance},
        updated_at = NOW()
      WHERE id = ${wallet.id}
    `;

    /*
     * Record the approved deposit in the
     * transactions ledger.
     */
    const transactionReference =
      `DEP-${String(item.deposit_reference || id)}-${crypto.randomUUID()}`;

    try {

      await sql`
        INSERT INTO transactions (
          id,
          user_id,
          wallet_id,
          transaction_reference,
          transaction_type,
          direction,
          amount,
          fee,
          currency,
          status,
          description,
          metadata,
          created_at,
          updated_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${item.user_id},
          ${wallet.id},
          ${transactionReference},
          'deposit',
          'credit',
          ${amount},
          0,
          ${item.currency || "USD"},
          'completed',
          'Deposit approved by administrator',
          ${JSON.stringify({
            source: "deposit_request_approval",
            request_id: item.id,
            deposit_reference:
              item.deposit_reference || null
          })},
          NOW(),
          NOW()
        )
      `;

    } catch (transactionError) {

      /*
       * Do not leave the customer with a credited
       * wallet if the required ledger entry failed.
       */
      await sql`
        UPDATE wallets
        SET
          balance = ${oldBalance},
          updated_at = NOW()
        WHERE id = ${wallet.id}
      `;

      console.error(
        "Deposit transaction creation error:",
        transactionError
      );

      return bad(
        500,
        "Deposit could not be approved because the transaction ledger could not be updated.",
        {
          detail:
            transactionError?.message ||
            "Transaction creation failed."
        }
      );
    }

    /*
     * Mark the deposit request approved only after
     * the wallet and transaction have succeeded.
     */
    const updated =
      await sql`
        UPDATE deposit_requests
        SET
          status = 'approved',
          reviewed_by = ${admin.user.id},
          reviewed_at = NOW(),
          updated_at = NOW()
        WHERE id = ${id}
          AND LOWER(COALESCE(status, 'pending'))
            = 'pending'
        RETURNING *
      `;

    if (!updated.length) {

      /*
       * Safety rollback if the request changed between
       * the initial check and this update.
       */
      await sql`
        UPDATE wallets
        SET
          balance = ${oldBalance},
          updated_at = NOW()
        WHERE id = ${wallet.id}
      `;

      return bad(
        400,
        "Deposit could not be approved because the request is no longer pending."
      );
    }

    return ok({
      message:
        "Deposit request approved successfully.",
      request: {
        ...updated[0],
        type: "deposit"
      }
    });
  }

  /*
   * =====================================================
   * APPROVE WITHDRAWAL
   * =====================================================
   *
   * Withdrawal approval:
   * 1. Check the customer's Main Wallet.
   * 2. Make sure there is enough balance.
   * 3. Debit the requested amount.
   * 4. Create the transaction ledger entry.
   * 5. Mark the withdrawal approved.
   */

  if (requestType === "withdrawal") {

    await ensureUserWallets(
      item.user_id
    );

    const walletRows =
      await sql`
        SELECT *
        FROM wallets
        WHERE user_id = ${item.user_id}
          AND id = ${item.wallet_id}
        LIMIT 1
      `;

    if (!walletRows.length) {
      return bad(
        500,
        "Withdrawal wallet could not be found."
      );
    }

    const wallet =
      walletRows[0];

    const oldBalance =
      numberValue(
        wallet.balance,
        0
      );

    if (oldBalance < amount) {
      return bad(
        400,
        "Insufficient Main Wallet balance for this withdrawal."
      );
    }

    const newBalance =
      oldBalance - amount;

    /*
     * Debit the customer's Main Wallet.
     */
    await sql`
      UPDATE wallets
      SET
        balance = ${newBalance},
        updated_at = NOW()
      WHERE id = ${wallet.id}
    `;

    const transactionId =
      crypto.randomUUID();

    const transactionReference =
      `WTH-${String(item.withdrawal_reference || id)}-${crypto.randomUUID()}`;

    try {

      await sql`
        INSERT INTO transactions (
          id,
          user_id,
          wallet_id,
          transaction_reference,
          transaction_type,
          direction,
          amount,
          fee,
          currency,
          status,
          description,
          metadata,
          created_at,
          updated_at
        )
        VALUES (
          ${transactionId},
          ${item.user_id},
          ${wallet.id},
          ${transactionReference},
          'withdrawal',
          'debit',
          ${amount},
          ${numberValue(item.fee, 0)},
          ${item.currency || "USD"},
          'completed',
          'Withdrawal approved by administrator',
          ${JSON.stringify({
            source: "withdrawal_request_approval",
            request_id: item.id,
            withdrawal_reference:
              item.withdrawal_reference || null,
            withdrawal_method:
              item.withdrawal_method || null
          })},
          NOW(),
          NOW()
        )
      `;

    } catch (transactionError) {

      /*
       * Roll the wallet back if the ledger entry fails.
       */
      await sql`
        UPDATE wallets
        SET
          balance = ${oldBalance},
          updated_at = NOW()
        WHERE id = ${wallet.id}
      `;

      console.error(
        "Withdrawal transaction creation error:",
        transactionError
      );

      return bad(
        500,
        "Withdrawal could not be approved because the transaction ledger could not be updated.",
        {
          detail:
            transactionError?.message ||
            "Transaction creation failed."
        }
      );
    }

    /*
     * Mark the withdrawal approved and connect
     * the resulting transaction.
     */
    const updated =
      await sql`
        UPDATE withdrawal_requests
        SET
          status = 'approved',
          reviewed_by = ${admin.user.id},
          reviewed_at = NOW(),
          processed_at = NOW(),
          transaction_id = ${transactionId},
          updated_at = NOW()
        WHERE id = ${id}
          AND LOWER(COALESCE(status, 'pending'))
            = 'pending'
        RETURNING *
      `;

    if (!updated.length) {

      /*
       * Safety rollback.
       */
      await sql`
        UPDATE wallets
        SET
          balance = ${oldBalance},
          updated_at = NOW()
        WHERE id = ${wallet.id}
      `;

      return bad(
        400,
        "Withdrawal could not be approved because the request is no longer pending."
      );
    }

    return ok({
      message:
        "Withdrawal request approved successfully.",
      request: {
        ...updated[0],
        type: "withdrawal"
      }
    });
  }

  return bad(
    400,
    "Unsupported request type."
  );
}

/* =====================================================
   ADMIN CHAT CONVERSATIONS — FIXED
===================================================== */

async function adminConversations() {
  const ready =
    await ensureChatFoundation();

  if (!ready) {
    return bad(
      500,
      "Unable to initialize Admin Chat."
    );
  }

  try {
    const rows =
      await sql`
        SELECT
          c.*,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM chat_conversations c
        LEFT JOIN profiles p
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
  } catch (error) {
    console.error(
      "Admin conversations error:",
      error
    );

    /*
     * Minimal fallback without profile join.
     */
    try {
      const rows =
        await sql`
          SELECT *
          FROM chat_conversations
          ORDER BY
            COALESCE(
              updated_at,
              created_at
            ) DESC
        `;

      return ok({
        conversations:
          rows
      });
    } catch (fallbackError) {
      return bad(
        500,
        "Unable to load chat conversations.",
        {
          detail:
            fallbackError?.message ||
            error?.message
        }
      );
    }
  }
}

/* =====================================================
   ADMIN CHAT MESSAGES — FIXED
===================================================== */

async function adminMessages(
  conversationId
) {
  if (!conversationId) {
    return bad(
      400,
      "Conversation ID is required."
    );
  }

  const ready =
    await ensureChatFoundation();

  if (!ready) {
    return bad(
      500,
      "Unable to initialize Admin Chat."
    );
  }

  try {
    const rows =
      await sql`
        SELECT
          *
        FROM chat_messages
        WHERE conversation_id =
          ${conversationId}
        ORDER BY created_at ASC
      `;

    return ok({
      messages:
        rows
    });
  } catch (error) {
    console.error(
      "Admin messages error:",
      error
    );

    return bad(
      500,
      "Unable to load chat messages.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   ADMIN SEND MESSAGE — FIXED
===================================================== */

async function adminSendMessage(
  request,
  conversationId,
  body
) {
  const admin =
    await requireAdmin(request);

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

  const ready =
    await ensureChatFoundation();

  if (!ready) {
    return bad(
      500,
      "Unable to initialize Admin Chat."
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
    rows =
      await sql`
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
      "Admin message insert error:",
      error
    );

    return bad(
      500,
      "Unable to send message.",
      {
        detail:
          error?.message
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
  } catch {
    /* optional column */
  }

  return ok({
    message:
      "Message sent.",
    data:
      rows[0]
  });
}

/* =====================================================
   ADMIN ACTIVITY — FIXED
===================================================== */

/*
 * Activity was previously built from only:
 *
 *   transactions
 *   investments
 *
 * That means wallet adjustments, wallet ledger entries,
 * requests and chat activity could never appear.
 *
 * The new version gathers every available source
 * independently. A missing optional table does not
 * break the whole Activity endpoint.
 */

async function adminActivity() {
  const activities = [];

  /*
   * TRANSACTIONS
   */
  try {
    const rows =
      await sql`
        SELECT
          t.id,
          'transaction' AS activity_type,
          COALESCE(
            t.type,
            'transaction'
          ) AS action,
          t.amount,
          t.direction,
          t.status,
          t.currency,
          t.description,
          t.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          t.created_at
        FROM transactions t
        LEFT JOIN profiles p
          ON p.id = t.user_id
        ORDER BY t.created_at DESC
        LIMIT 50
      `;

    activities.push(
      ...rows
    );
  } catch (error) {
    console.warn(
      "Activity transactions unavailable:",
      error?.message
    );
  }

  /*
   * INVESTMENTS
   */
  try {
    const rows =
      await sql`
        SELECT
          i.id,
          'investment' AS activity_type,
          'investment_created'
            AS action,
          COALESCE(
            i.principal_amount,
            i.amount,
            0
          ) AS amount,
          NULL AS direction,
          i.status,
          'USD' AS currency,
          NULL AS description,
          i.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          i.created_at
        FROM investments i
        LEFT JOIN profiles p
          ON p.id = i.user_id
        ORDER BY i.created_at DESC
        LIMIT 50
      `;

    activities.push(
      ...rows
    );
  } catch (error) {
    console.warn(
      "Activity investments unavailable:",
      error?.message
    );

    /*
     * Compatibility fallback if investments does not
     * have principal_amount.
     */
    try {
      const rows =
        await sql`
          SELECT
            i.id,
            'investment' AS activity_type,
            'investment_created'
              AS action,
            i.amount,
            NULL AS direction,
            i.status,
            'USD' AS currency,
            NULL AS description,
            i.user_id,
            p.first_name,
            p.last_name,
            p.username,
            p.email,
            i.created_at
          FROM investments i
          LEFT JOIN profiles p
            ON p.id = i.user_id
          ORDER BY i.created_at DESC
          LIMIT 50
        `;

      activities.push(
        ...rows
      );
    } catch (fallbackError) {
      console.warn(
        "Activity investment fallback unavailable:",
        fallbackError?.message
      );
    }
  }

  /*
   * WALLET LEDGER
   */
  try {
    const rows =
      await sql`
        SELECT
          wl.id,
          'wallet' AS activity_type,
          COALESCE(
            wl.entry_type,
            'wallet_activity'
          ) AS action,
          wl.amount,
          CASE
            WHEN wl.amount >= 0
              THEN 'credit'
            ELSE 'debit'
          END AS direction,
          'completed' AS status,
          'USD' AS currency,
          wl.description,
          wl.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          wl.created_at
        FROM wallet_ledger wl
        LEFT JOIN profiles p
          ON p.id = wl.user_id
        ORDER BY wl.created_at DESC
        LIMIT 50
      `;

    activities.push(
      ...rows
    );
  } catch (error) {
    console.warn(
      "Activity wallet ledger unavailable:",
      error?.message
    );
  }

  /*
   * PENDING / PROCESSED REQUESTS
   */
  try {
    const rows =
      await sql`
        SELECT
          r.id,
          'request' AS activity_type,
          COALESCE(
            r.type,
            'request'
          ) AS action,
          r.amount,
          NULL AS direction,
          r.status,
          'USD' AS currency,
          NULL AS description,
          r.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          r.created_at
        FROM pending_requests r
        LEFT JOIN profiles p
          ON p.id = r.user_id
        ORDER BY r.created_at DESC
        LIMIT 50
      `;

    activities.push(
      ...rows
    );
  } catch (error) {
    console.warn(
      "Activity requests unavailable:",
      error?.message
    );
  }

  /*
   * CHAT
   */
  try {
    const ready =
      await ensureChatFoundation();

    if (ready) {
      const rows =
        await sql`
          SELECT
            m.id,
            'chat' AS activity_type,
            CASE
              WHEN LOWER(
                COALESCE(
                  m.sender_type,
                  ''
                )
              ) = 'admin'
                THEN 'admin_message'
              ELSE 'customer_message'
            END AS action,
            NULL AS amount,
            NULL AS direction,
            'completed' AS status,
            NULL AS currency,
            m.message AS description,
            c.user_id,
            p.first_name,
            p.last_name,
            p.username,
            p.email,
            m.created_at
          FROM chat_messages m
          LEFT JOIN chat_conversations c
            ON c.id =
              m.conversation_id
          LEFT JOIN profiles p
            ON p.id =
              c.user_id
          ORDER BY m.created_at DESC
          LIMIT 30
        `;

      activities.push(
        ...rows
      );
    }
  } catch (error) {
    console.warn(
      "Activity chat unavailable:",
      error?.message
    );
  }

  /*
   * Sort everything together.
   */
  activities.sort(
    (a, b) => {
      const dateA =
        new Date(
          a.created_at || 0
        ).getTime();

      const dateB =
        new Date(
          b.created_at || 0
        ).getTime();

      return dateB - dateA;
    }
  );

  return ok({
    activity:
      activities.slice(0, 50),
    activities:
      activities.slice(0, 50)
  });
}

/* =====================================================
   ADMIN UPDATE CUSTOMER
===================================================== */

async function updateCustomer(
  request,
  id,
  body
) {
  const admin =
    await requireAdmin(request);

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

  const current =
    await sql`
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
      ? String(
          body.first_name
        ).trim()
      : null;

  const lastName =
    body.last_name !== undefined
      ? String(
          body.last_name
        ).trim()
      : null;

  const username =
    body.username !== undefined
      ? String(
          body.username
        ).trim()
      : null;

  const status =
    body.status !== undefined
      ? String(
          body.status
        ).trim()
      : null;

  const kycStatus =
    body.kyc_status !== undefined
      ? String(
          body.kyc_status
        ).trim()
      : null;

  const updated =
    await sql`
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

  await ensureUserWallets(id);

  return ok({
    message:
      "Customer updated successfully.",
    customer:
      updated[0]
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
    normalizeEmail(
      body.email
    );

  const password =
    String(
      body.password || ""
    );

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

  const result =
    await sql`
      UPDATE auth_credentials
      SET
        password_hash =
          ${passwordHash},
        password_updated_at =
          NOW(),
        failed_login_attempts = 0,
        locked_until = NULL,
        updated_at = NOW()
      WHERE user_id = (
        SELECT p.id
        FROM profiles p
        INNER JOIN roles r
          ON r.id = p.role_id
        WHERE
          LOWER(p.email) =
            ${email}
          AND LOWER(r.name) =
            'admin'
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

  const result =
    await sql`
      SELECT
        t.id AS token_id,
        t.user_id
      FROM auth_email_tokens t
      WHERE
        t.token_hash =
          ${tokenHash}
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

  const item =
    result[0];

  await sql`
    UPDATE profiles
    SET
      email_verified_at =
        NOW(),
      updated_at = NOW()
    WHERE id =
      ${item.user_id}
  `;

  await sql`
    UPDATE auth_email_tokens
    SET used_at = NOW()
    WHERE id =
      ${item.token_id}
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
      req.headers[
        "x-forwarded-proto"
      ] ||
        "https"
    )
      .split(",")[0]
      .trim();

  const host =
    String(
      req.headers[
        "x-forwarded-host"
      ] ||
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
      request.method ===
      "OPTIONS"
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
        await verifyEmail(
          body.token
        )
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
       ADMIN CUSTOMERS
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
        url.searchParams.get("id");

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

    if (
      (
        method === "PUT" ||
        method === "PATCH"
      ) &&
      path.startsWith(
        "/api/admin/customers/"
      )
    ) {
      const id =
        path.split("/").pop();

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
       ADMIN WALLETS
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
        url.searchParams.get(
          "user_id"
        );

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

    if (
      method === "POST" &&
      (
        path ===
          "/api/admin/wallets/adjust" ||
        path ===
          "/api/admin/wallet/adjust"
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
       ADMIN KYC
    ================================================= */

    if (
      method === "GET" &&
      path === "/api/admin/kyc"
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

    if (
      (
        method === "POST" ||
        method === "PATCH" ||
        method === "PUT"
      ) &&
      path.startsWith(
        "/api/admin/kyc/"
      )
    ) {
      const id =
        path.split("/").pop();

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
       ADMIN PENDING REQUESTS
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
        path.split("/").pop();

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
        path ===
          "/api/admin/chat" ||
        path ===
          "/api/admin/conversations"
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

    if (
      method === "GET" &&
      path.startsWith(
        "/api/admin/chat/"
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
        path.split("/").pop();

      return writeWebResponse(
        res,
        await adminMessages(
          conversationId
        )
      );
    }

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
      const parts =
        path.split("/");

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
