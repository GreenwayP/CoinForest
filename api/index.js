/* =====================================================
   COINFOREST API — COMPLETE INDEX.JS
   CUSTOMER + ADMIN FULL FIX
   =====================================================

   FULL REPLACEMENT VERSION
   - Customer wallet synchronization
   - Admin wallet adjustment synchronization
   - Customer transactions
   - Customer KYC application
   - Admin KYC synchronization
   - Admin approval => email verified
   - Unapproved customers can login but cannot perform actions
   - Deposit / Send / Withdrawal guards
   - Withdrawal account storage
   - Customer profile
   - Customer investments / portfolio
   - Customer chat
   - Admin chat
   - Admin activities
   - Admin transactions
   - Admin requests
   - Existing authentication preserved

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
      'pending',
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

  /*
   * Email verification is deliberately NOT required
   * for account approval or normal login.
   *
   * Resend/domain problems therefore cannot block
   * customer registration.
   */
  try {
    await sendVerificationEmail(
      request,
      user
    );
  } catch (error) {
    console.warn(
      "Verification email unavailable:",
      error?.message
    );
  }

  return response(201, {
    success: true,
    email_sent: false,
    message:
      "Account created successfully. Your account is awaiting administrator approval.",
    user
  });
}

/* =====================================================
   WALLET FOUNDATION
===================================================== */

async function ensureUserWallets(userId) {
  if (!userId) return;

  /*
   * Current wallet model.
   */
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
    /*
     * Legacy combined wallet compatibility.
     */
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
      p.kyc_status,
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
    message:
      "Login successful.",
    token,
    user: {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      role: user.role_name,
      status: user.status,
      kyc_status: user.kyc_status,
      account_approved:
        isApprovedStatus(user.status),

      /*
       * Administrator approval is the temporary
       * source of email verification.
       */
      email_verified:
        !!user.email_verified_at ||
        isApprovedStatus(user.status),

      email_verified_at:
        user.email_verified_at ||
        (
          isApprovedStatus(user.status)
            ? new Date().toISOString()
            : null
        )
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
      error:
        "Authentication required."
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

/* =====================================================
   ACCOUNT / KYC GUARDS
===================================================== */

function isApprovedStatus(status) {
  const value =
    String(status || "")
      .trim()
      .toLowerCase();

  return (
    value === "active" ||
    value === "approved" ||
    value === "verified"
  );
}

function isApprovedKyc(status) {
  return (
    String(status || "")
      .trim()
      .toLowerCase() ===
    "approved"
  );
}

function customerActionAllowed(
  user,
  { requireKyc = false } = {}
) {
  if (!isApprovedStatus(user?.status)) {
    return bad(
      403,
      "Your account is awaiting administrator approval. You can log in, but account actions are unavailable until your account is approved.",
      {
        code:
          "ACCOUNT_NOT_APPROVED",
        account_approved: false
      }
    );
  }

  if (
    requireKyc &&
    !isApprovedKyc(
      user?.kyc_status
    )
  ) {
    return bad(
      403,
      "KYC verification is required for this action.",
      {
        code: "KYC_REQUIRED",
        kyc_status:
          user?.kyc_status ||
          "pending"
      }
    );
  }

  return null;
}

async function requireAdmin(request) {
  const auth = await authenticate(request);

  if (!auth.ok) {
    return auth;
  }

  const role = String(
    auth.user?.role_name ||
    ""
  ).trim().toLowerCase();

  if (
    role !== "admin" &&
    role !== "administrator"
  ) {
    return {
      ok: false,
      status: 403,
      error:
        "Administrator access required.",
      user: auth.user,
      token: auth.token
    };
  }

  return auth;
}
async function requireCustomer(
  request,
  options = {}
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) return auth;

  const denied =
    options.requireApproval ||
    options.requireKyc
      ? customerActionAllowed(
          auth.user,
          options
        )
      : null;

  if (denied) {
    const data =
      await denied.json();

    return {
      ok: false,
      status: denied.status,
      error: data.error,
      code: data.code,
      account_approved:
        data.account_approved,
      user: auth.user,
      token: auth.token
    };
  }

  return auth;
}

async function requireApprovedCustomer(
  request,
  options = {}
) {
  const auth =
    await requireCustomer(request);

  if (!auth.ok) return auth;

  if (
    !isApprovedStatus(
      auth.user.status
    )
  ) {
    return {
      ok: false,
      status: 403,
      error:
        "Your account is awaiting administrator approval. Please wait until your account is approved before performing this action.",
      code:
        "ACCOUNT_NOT_APPROVED",
      account_approved: false,
      user: auth.user,
      token: auth.token
    };
  }

  if (
    options.requireKyc &&
    !isApprovedKyc(
      auth.user.kyc_status
    )
  ) {
    return {
      ok: false,
      status: 403,
      error:
        "KYC verification is required for this action.",
      code:
        "KYC_REQUIRED",
      kyc_status:
        auth.user.kyc_status ||
        "pending",
      user: auth.user,
      token: auth.token
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
      kyc_status:
        user.kyc_status,

      account_approved:
        isApprovedStatus(
          user.status
        ),

      email_verified:
        !!user.email_verified_at ||
        isApprovedStatus(
          user.status
        ),

      email_verified_at:
        user.email_verified_at ||
        (
          isApprovedStatus(
            user.status
          )
            ? new Date().toISOString()
            : null
        )
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
   CUSTOMER WALLET STATE
===================================================== */

async function loadCustomerWalletState(
  userId
) {
  await ensureUserWallets(userId);

  const rows = await sql`
    SELECT *
    FROM wallets
    WHERE user_id = ${userId}
    ORDER BY created_at ASC
  `;

  let main = null;
  let profit = null;
  let legacy = null;

  for (const wallet of rows) {
    const type =
      String(
        wallet.wallet_type || ""
      ).toLowerCase();

    if (
      type === "main" &&
      !main
    ) {
      main = wallet;
    }

    if (
      type === "profit" &&
      !profit
    ) {
      profit = wallet;
    }

    if (
      wallet.main_balance !==
        undefined ||
      wallet.profit_balance !==
        undefined
    ) {
      legacy = wallet;
    }
  }

  const typedMainBalance =
    main
      ? numberValue(
          main.balance,
          0
        )
      : 0;

  const typedProfitBalance =
    profit
      ? numberValue(
          profit.balance,
          0
        )
      : 0;

  const legacyMainBalance =
    legacy
      ? numberValue(
          legacy.main_balance,
          0
        )
      : 0;

  const legacyProfitBalance =
    legacy
      ? numberValue(
          legacy.profit_balance,
          0
        )
      : 0;

  if (!main && legacy) {
    main = legacy;
  }

  if (
    !profit &&
    legacy &&
    legacyProfitBalance !== 0
  ) {
    profit = legacy;
  }

  /*
   * Important:
   *
   * A real non-zero legacy balance must not be
   * hidden by a newly-created zero typed wallet.
   */
  const mainBalance =
    typedMainBalance !== 0 ||
    !legacy
      ? typedMainBalance
      : legacyMainBalance;

  const profitBalance =
    typedProfitBalance !== 0 ||
    !legacy
      ? typedProfitBalance
      : legacyProfitBalance;

  return {
    rows,
    main,
    profit,
    mainBalance,
    profitBalance,
    totalBalance:
      mainBalance +
      profitBalance
  };
}

/* =====================================================
   CUSTOMER WALLETS
===================================================== */

async function customerWallets(
  request
) {
  const auth =
    await requireCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  try {
    const state =
      await loadCustomerWalletState(
        auth.user.id
      );

    return ok({
      wallets: state.rows,
      main_wallet:
        state.main,
      profit_wallet:
        state.profit,

      main_balance:
        state.mainBalance,

      profit_balance:
        state.profitBalance,

      total_balance:
        state.totalBalance,

      account_approved:
        isApprovedStatus(
          auth.user.status
        ),

      email_verified:
        !!auth.user.email_verified_at ||
        isApprovedStatus(
          auth.user.status
        ),

      kyc_status:
        auth.user.kyc_status ||
        "pending"
    });
  } catch (error) {
    console.error(
      "Customer wallets error:",
      error
    );

    return bad(
      500,
      "Unable to load customer wallets.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   CUSTOMER TRANSACTIONS
===================================================== */

async function loadCustomerTransactions(
  userId,
  limit
) {
  let rows = [];

  try {
    rows = await sql`
      SELECT *
      FROM transactions
      WHERE user_id = ${userId}
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;
  } catch (error) {
    console.warn(
      "Customer transactions query warning:",
      error?.message
    );
  }

  /*
   * Wallet adjustments also live in wallet_ledger.
   * Include them so Admin wallet adjustments appear
   * in the customer's history.
   */
  try {
    const ledger =
      await sql`
        SELECT *
        FROM wallet_ledger
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
        LIMIT ${limit}
      `;

    const existingKeys =
      new Set(
        rows.map(
          row =>
            `${row.transaction_reference || ""}|${row.created_at || ""}`
        )
      );

    for (const item of ledger) {
      const key =
        `LEDGER|${item.created_at || ""}|${item.id || ""}`;

      if (
        !existingKeys.has(key)
      ) {
        rows.push({
          ...item,

          id:
            item.id,

          transaction_reference:
            item.transaction_reference ||
            `LEDGER-${item.id}`,

          transaction_type:
            item.entry_type ||
            "wallet_adjustment",

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

          currency:
            item.currency ||
            "USD",

          status:
            item.status ||
            "success",

          description:
            item.description ||
            "Wallet activity",

          metadata:
            item.metadata ||
            {
              source:
                "wallet_ledger"
            }
        });
      }
    }
  } catch (error) {
    console.warn(
      "Wallet ledger unavailable:",
      error?.message
    );
  }

  rows.sort(
    (a, b) =>
      new Date(
        b.created_at || 0
      ).getTime() -
      new Date(
        a.created_at || 0
      ).getTime()
  );

  return rows.slice(
    0,
    limit
  );
}

async function customerTransactions(
  request,
  url
) {
  const auth =
    await requireCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  try {
    const limit =
      cleanLimit(
        url.searchParams.get(
          "limit"
        ),
        100
      );

    const rows =
      await loadCustomerTransactions(
        auth.user.id,
        limit
      );

    return ok({
      transactions: rows,
      count: rows.length
    });
  } catch (error) {
    return bad(
      500,
      "Unable to load customer transactions.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   CUSTOMER DASHBOARD
===================================================== */

async function customerDashboard(
  request
) {
  const auth =
    await requireCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  try {
    const walletState =
      await loadCustomerWalletState(
        auth.user.id
      );

    const transactions =
      await loadCustomerTransactions(
        auth.user.id,
        100
      );

    let investments = [];

    try {
      investments =
        await sql`
          SELECT *
          FROM investments
          WHERE user_id =
            ${auth.user.id}
          ORDER BY created_at DESC
          LIMIT 100
        `;
    } catch (error) {
      console.warn(
        "Customer investments unavailable:",
        error?.message
      );
    }

    const profileRows =
      await sql`
        SELECT *
        FROM profiles
        WHERE id =
          ${auth.user.id}
        LIMIT 1
      `;

    const profile =
      profileRows[0] ||
      auth.user;

    const approved =
      isApprovedStatus(
        profile.status
      );

    return ok({
      user: profile,
      profile,

      wallets:
        walletState.rows,

      main_wallet:
        walletState.main,

      profit_wallet:
        walletState.profit,

      main_balance:
        walletState.mainBalance,

      profit_balance:
        walletState.profitBalance,

      total_balance:
        walletState.totalBalance,

      transactions,
      investments,

      account_approved:
        approved,

      email_verified:
        !!profile.email_verified_at ||
        approved,

      email_verified_at:
        profile.email_verified_at ||
        (
          approved
            ? new Date().toISOString()
            : null
        ),

      kyc_status:
        String(
          profile.kyc_status ||
          "pending"
        ).toLowerCase()
    });
  } catch (error) {
    console.error(
      "Customer dashboard error:",
      error
    );

    return bad(
      500,
      "Unable to load customer dashboard.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   CUSTOMER PROFILE
===================================================== */

async function customerProfile(
  request,
  body = null
) {
  const auth =
    await requireApprovedCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  if (!body) {
    const rows =
      await sql`
        SELECT *
        FROM profiles
        WHERE id =
          ${auth.user.id}
        LIMIT 1
      `;

    return ok({
      profile:
        rows[0] ||
        auth.user,

      user:
        rows[0] ||
        auth.user
    });
  }

  const firstName =
    body.first_name !==
    undefined
      ? String(
          body.first_name
        ).trim()
      : null;

  const lastName =
    body.last_name !==
    undefined
      ? String(
          body.last_name
        ).trim()
      : null;

  const username =
    body.username !==
    undefined
      ? String(
          body.username
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
        updated_at = NOW()
      WHERE id =
        ${auth.user.id}
      RETURNING *
    `;

  return ok({
    message:
      "Profile updated successfully.",

    profile:
      updated[0]
  });
}

/* =====================================================
   CUSTOMER KYC
===================================================== */

async function customerKyc(
  request,
  body = null
) {
  const auth =
    await requireCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  const profileRows =
    await sql`
      SELECT *
      FROM profiles
      WHERE id =
        ${auth.user.id}
      LIMIT 1
    `;

  const profile =
    profileRows[0] ||
    auth.user;

  if (!body) {
    let submissions = [];

    try {
      submissions =
        await sql`
          SELECT *
          FROM kyc_submissions
          WHERE user_id =
            ${auth.user.id}
          ORDER BY created_at DESC
          LIMIT 20
        `;
    } catch (error) {
      console.warn(
        "KYC submissions unavailable:",
        error?.message
      );
    }

    return ok({
      kyc_status:
        profile.kyc_status ||
        "pending",

      profile,
      submissions
    });
  }

  if (
    !isApprovedStatus(
      profile.status
    )
  ) {
    return bad(
      403,
      "Your account is awaiting administrator approval. Please wait until your account is approved before submitting KYC.",
      {
        code:
          "ACCOUNT_NOT_APPROVED",
        account_approved: false
      }
    );
  }

  const current =
    String(
      profile.kyc_status ||
      "pending"
    ).toLowerCase();

  if (current === "approved") {
    return ok({
      message:
        "KYC is already approved.",
      kyc_status:
        "approved"
    });
  }

  let existing = [];

  try {
    existing =
      await sql`
        SELECT id
        FROM kyc_submissions
        WHERE user_id =
          ${auth.user.id}
          AND LOWER(
            COALESCE(
              status,
              'pending'
            )
          ) = 'pending'
        ORDER BY created_at DESC
        LIMIT 1
      `;
  } catch (error) {
    /*
     * If the submissions table does not exist,
     * return a clear error rather than pretending
     * the application was submitted.
     */
    return bad(
      500,
      "Unable to submit KYC application.",
      {
        detail:
          error?.message
      }
    );
  }

  if (existing.length) {
    return bad(
      409,
      "A KYC application is already pending."
    );
  }

  const id =
    crypto.randomUUID();

  try {
    await sql`
      INSERT INTO kyc_submissions (
        id,
        user_id,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${id},
        ${auth.user.id},
        'pending',
        NOW(),
        NOW()
      )
    `;
  } catch (error) {
    return bad(
      500,
      "Unable to submit KYC application.",
      {
        detail:
          error?.message
      }
    );
  }

  await sql`
    UPDATE profiles
    SET
      kyc_status = 'pending',
      updated_at = NOW()
    WHERE id =
      ${auth.user.id}
  `;

  return ok({
    message:
      "KYC application submitted successfully.",

    kyc_status:
      "pending",

    submission_id:
      id
  });
}

/* =====================================================
   KYC HELPER
===================================================== */

function kycRequired(user) {
  return (
    String(
      user?.kyc_status ||
      "pending"
    ).toLowerCase() !==
    "approved"
  );
}

/* =====================================================
   CUSTOMER DEPOSIT
===================================================== */

async function customerDeposit(
  request,
  body
) {
  const auth =
    await requireApprovedCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  if (
    kycRequired(
      auth.user
    )
  ) {
    return bad(
      403,
      "KYC verification is required before making a deposit.",
      {
        code:
          "KYC_REQUIRED",
        kyc_status:
          auth.user.kyc_status ||
          "pending"
      }
    );
  }

  const amount =
    numberValue(
      body.amount,
      NaN
    );

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Deposit amount must be greater than zero."
    );
  }

  await ensureUserWallets(
    auth.user.id
  );

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${auth.user.id}
        AND wallet_type =
          'main'
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      500,
      "Main wallet could not be found."
    );
  }

  const wallet =
    walletRows[0];

  const reference =
    `DEP-${crypto.randomUUID()}`;

  let paymentMethod =
    String(
      body.payment_method ||
      body.paymentMethod ||
      "Bank Transfer"
    ).trim();

  let paymentReference =
    String(
      body.payment_reference ||
      body.paymentReference ||
      ""
    ).trim() || null;

  try {
    const rows =
      await sql`
        INSERT INTO deposit_requests (
          id,
          deposit_reference,
          user_id,
          wallet_id,
          amount,
          currency,
          payment_method,
          payment_reference,
          status,
          submitted_at,
          updated_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${reference},
          ${auth.user.id},
          ${wallet.id},
          ${amount},
          'USD',
          ${paymentMethod},
          ${paymentReference},
          'pending',
          NOW(),
          NOW()
        )
        RETURNING *
      `;

    return ok({
      message:
        "Deposit request submitted successfully.",

      request:
        rows[0]
    });
  } catch (error) {
    return bad(
      500,
      "Unable to submit deposit request.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   CUSTOMER SEND
===================================================== */

async function customerSend(
  request,
  body
) {
  const auth =
    await requireApprovedCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  if (
    kycRequired(
      auth.user
    )
  ) {
    return bad(
      403,
      "KYC verification is required before sending funds.",
      {
        code:
          "KYC_REQUIRED",
        kyc_status:
          auth.user.kyc_status ||
          "pending"
      }
    );
  }

  const amount =
    numberValue(
      body.amount,
      NaN
    );

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Send amount must be greater than zero."
    );
  }

  const recipient =
    normalizeEmail(
      body.recipient_email ||
      body.recipientEmail ||
      body.email
    );

  if (!recipient) {
    return bad(
      400,
      "Recipient email is required."
    );
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${auth.user.id}
        AND wallet_type =
          'main'
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      500,
      "Main wallet could not be found."
    );
  }

  const senderWallet =
    walletRows[0];

  const senderBalance =
    numberValue(
      senderWallet.balance,
      0
    );

  if (
    senderBalance < amount
  ) {
    return bad(
      400,
      "Insufficient Main Wallet balance.",
      {
        code:
          "INSUFFICIENT_BALANCE",
        balance:
          senderBalance,
        required:
          amount
      }
    );
  }

  const recipientRows =
    await sql`
      SELECT id, email
      FROM profiles
      WHERE LOWER(email) =
        ${recipient}
      LIMIT 1
    `;

  if (!recipientRows.length) {
    return bad(
      404,
      "Recipient account was not found."
    );
  }

  const recipientId =
    recipientRows[0].id;

  if (
    recipientId ===
    auth.user.id
  ) {
    return bad(
      400,
      "You cannot send funds to yourself."
    );
  }

  await ensureUserWallets(
    recipientId
  );

  const recipientWalletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${recipientId}
        AND wallet_type =
          'main'
      LIMIT 1
    `;

  if (
    !recipientWalletRows.length
  ) {
    return bad(
      500,
      "Recipient Main Wallet could not be found."
    );
  }

  const recipientWallet =
    recipientWalletRows[0];

  const senderNew =
    senderBalance -
    amount;

  const recipientOld =
    numberValue(
      recipientWallet.balance,
      0
    );

  const recipientNew =
    recipientOld +
    amount;

  const reference =
    `SND-${crypto.randomUUID()}`;

  try {
    await sql`
      UPDATE wallets
      SET
        balance = ${senderNew},
        updated_at = NOW()
      WHERE id =
        ${senderWallet.id}
    `;

    await sql`
      UPDATE wallets
      SET
        balance = ${recipientNew},
        updated_at = NOW()
      WHERE id =
        ${recipientWallet.id}
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
          created_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${auth.user.id},
          'main',
          ${-amount},
          ${senderBalance},
          ${senderNew},
          'send',
          ${`Transfer sent to ${recipient}`},
          NOW()
        )
      `;
    } catch (error) {
      console.warn(
        "Sender ledger warning:",
        error?.message
      );
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
          created_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${recipientId},
          'main',
          ${amount},
          ${recipientOld},
          ${recipientNew},
          'receive',
          ${`Transfer received from ${auth.user.email}`},
          NOW()
        )
      `;
    } catch (error) {
      console.warn(
        "Recipient ledger warning:",
        error?.message
      );
    }

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
          ${auth.user.id},
          ${senderWallet.id},
          ${reference},
          'transfer',
          'debit',
          ${amount},
          0,
          'USD',
          'success',
          ${`Transfer sent to ${recipient}`},
          ${JSON.stringify({
            recipient_id:
              recipientId,
            recipient_email:
              recipient,
            source:
              "customer_send"
          })},
          NOW(),
          NOW()
        )
      `;
    } catch (error) {
      console.warn(
        "Send transaction warning:",
        error?.message
      );
    }

    return ok({
      message:
        "Funds sent successfully.",
      transaction_reference:
        reference,
      amount,
      balance:
        senderNew
    });
  } catch (error) {
    /*
     * Best-effort rollback.
     */
    try {
      await sql`
        UPDATE wallets
        SET
          balance =
            ${senderBalance},
          updated_at = NOW()
        WHERE id =
          ${senderWallet.id}
      `;

      await sql`
        UPDATE wallets
        SET
          balance =
            ${recipientOld},
          updated_at = NOW()
        WHERE id =
          ${recipientWallet.id}
      `;
    } catch (rollbackError) {
      console.error(
        "Send rollback failed:",
        rollbackError
      );
    }

    return bad(
      500,
      "Unable to complete the transfer.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   WITHDRAWAL ACCOUNT STORAGE
===================================================== */

async function ensureWithdrawalAccountSchema() {
  await sql`
    CREATE TABLE IF NOT EXISTS withdrawal_accounts (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL UNIQUE,
      method_name TEXT NOT NULL DEFAULT 'Bank Transfer',
      account_name TEXT NOT NULL,
      account_number TEXT NOT NULL,
      bank_name TEXT NOT NULL,
      swift_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
}

async function customerWithdrawalAccount(
  request,
  body = null
) {
  const auth =
    await requireApprovedCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  try {
    await ensureWithdrawalAccountSchema();
  } catch (error) {
    return bad(
      500,
      "Unable to prepare withdrawal account storage.",
      {
        detail:
          error?.message
      }
    );
  }

  if (!body) {
    const rows =
      await sql`
        SELECT *
        FROM withdrawal_accounts
        WHERE user_id =
          ${auth.user.id}
        LIMIT 1
      `;

    return ok({
      account:
        rows[0] ||
        null,

      has_account:
        !!rows.length
    });
  }

  const accountName =
    String(
      body.account_name ||
      body.accountName ||
      ""
    ).trim();

  const accountNumber =
    String(
      body.account_number ||
      body.accountNumber ||
      ""
    ).trim();

  const bankName =
    String(
      body.bank_name ||
      body.bankName ||
      ""
    ).trim();

  const swiftCode =
    String(
      body.swift_code ||
      body.swift ||
      body.other_code ||
      ""
    ).trim() || null;

  if (
    !accountName ||
    !accountNumber ||
    !bankName
  ) {
    return bad(
      400,
      "Account name, account number and bank name are required."
    );
  }

  const existing =
    await sql`
      SELECT id
      FROM withdrawal_accounts
      WHERE user_id =
        ${auth.user.id}
      LIMIT 1
    `;

  if (existing.length) {
    const updated =
      await sql`
        UPDATE withdrawal_accounts
        SET
          method_name =
            'Bank Transfer',

          account_name =
            ${accountName},

          account_number =
            ${accountNumber},

          bank_name =
            ${bankName},

          swift_code =
            ${swiftCode},

          updated_at =
            NOW()

        WHERE user_id =
          ${auth.user.id}

        RETURNING *
      `;

    return ok({
      message:
        "Withdrawal account updated successfully.",

      account:
        updated[0]
    });
  }

  const created =
    await sql`
      INSERT INTO withdrawal_accounts (
        id,
        user_id,
        method_name,
        account_name,
        account_number,
        bank_name,
        swift_code,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${auth.user.id},
        'Bank Transfer',
        ${accountName},
        ${accountNumber},
        ${bankName},
        ${swiftCode},
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  return ok({
    message:
      "Withdrawal account saved successfully.",

    account:
      created[0]
  });
}

/* =====================================================
   CUSTOMER WITHDRAWAL
===================================================== */

async function customerWithdraw(
  request,
  body
) {
  const auth =
    await requireCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  if (
    !isApprovedStatus(
      auth.user.status
    )
  ) {
    return bad(
      403,
      "Your account is awaiting administrator approval.",
      {
        code:
          "ACCOUNT_NOT_APPROVED",
        account_approved:
          false
      }
    );
  }

  if (
    kycRequired(
      auth.user
    )
  ) {
    return bad(
      403,
      "KYC verification is required before making a withdrawal.",
      {
        code:
          "KYC_REQUIRED",
        kyc_status:
          auth.user.kyc_status ||
          "pending"
      }
    );
  }

  const amount =
    numberValue(
      body.amount,
      NaN
    );

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Withdrawal amount must be greater than zero."
    );
  }

  await ensureWithdrawalAccountSchema();

  const accountRows =
    await sql`
      SELECT *
      FROM withdrawal_accounts
      WHERE user_id =
        ${auth.user.id}
      LIMIT 1
    `;

  if (!accountRows.length) {
    return bad(
      409,
      "Please add your withdrawal bank account details before making a withdrawal.",
      {
        code:
          "WITHDRAWAL_ACCOUNT_REQUIRED",

        requires_withdrawal_account:
          true
      }
    );
  }

  await ensureUserWallets(
    auth.user.id
  );

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${auth.user.id}
        AND wallet_type =
          'main'
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      500,
      "Main wallet could not be found."
    );
  }

  const wallet =
    walletRows[0];

  const balance =
    numberValue(
      wallet.balance,
      0
    );

  if (
    balance < amount
  ) {
    return bad(
      400,
      "Insufficient Main Wallet balance.",
      {
        code:
          "INSUFFICIENT_BALANCE",

        balance,

        required:
          amount
      }
    );
  }

  const reference =
    `WTH-${crypto.randomUUID()}`;

  try {
    const rows =
      await sql`
        INSERT INTO withdrawal_requests (
          id,
          withdrawal_reference,
          user_id,
          wallet_id,
          amount,
          fee,
          net_amount,
          currency,
          withdrawal_method,
          status,
          requested_at,
          updated_at,
          withdrawal_account_id
        )
        VALUES (
          ${crypto.randomUUID()},
          ${reference},
          ${auth.user.id},
          ${wallet.id},
          ${amount},
          0,
          ${amount},
          'USD',
          'Bank Transfer',
          'pending',
          NOW(),
          NOW(),
          ${accountRows[0].id}
        )
        RETURNING *
      `;

    return ok({
      message:
        "Withdrawal request submitted successfully.",

      request:
        rows[0],

      account:
        accountRows[0]
    });
  } catch (error) {
    return bad(
      500,
      "Unable to submit withdrawal request.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   CUSTOMER INVESTMENTS / PORTFOLIO
===================================================== */

async function customerInvestments(
  request,
  url
) {
  const auth =
    await requireCustomer(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error,
      auth
    );
  }

  try {
    const rows =
      await sql`
        SELECT *
        FROM investments
        WHERE user_id =
          ${auth.user.id}
        ORDER BY created_at DESC
        LIMIT ${
          cleanLimit(
            url.searchParams.get(
              "limit"
            ),
            100
          )
        }
      `;

    return ok({
      investments:
        rows,

      portfolio:
        rows
    });
  } catch (error) {
    return bad(
      500,
      "Unable to load customer investments.",
      {
        detail:
          error?.message
      }
    );
  }
}
/* =====================================================
   ADMIN REQUESTS
===================================================== */

async function adminRequests(request, url, body = null, requestId = null) {

  const auth = await requireAdmin(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  /*
   * GET /api/admin/requests
   *
   * Combines pending deposit, withdrawal
   * and transfer requests into one list.
   */

  if (!body && !requestId) {

    const status =
      String(
        url.searchParams.get("status") ||
        "pending"
      ).trim().toLowerCase();

    const limit =
      cleanLimit(
        url.searchParams.get("limit"),
        500
      );

    const deposits =
      await sql`
        SELECT
          d.*,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM deposit_requests d
        LEFT JOIN profiles p
          ON p.id = d.user_id
        WHERE LOWER(
          COALESCE(d.status, 'pending')
        ) = ${status}
        ORDER BY d.created_at DESC
        LIMIT ${limit}
      `;

    const withdrawals =
      await sql`
        SELECT
          w.*,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM withdrawal_requests w
        LEFT JOIN profiles p
          ON p.id = w.user_id
        WHERE LOWER(
          COALESCE(w.status, 'pending')
        ) = ${status}
        ORDER BY w.created_at DESC
        LIMIT ${limit}
      `;

    const transfers =
      await sql`
        SELECT
          t.*,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM transfer_requests t
        LEFT JOIN profiles p
          ON p.id = t.sender_user_id
        WHERE LOWER(
          COALESCE(t.status, 'pending')
        ) = ${status}
        ORDER BY t.created_at DESC
        LIMIT ${limit}
      `;

    const requests = [
      ...deposits.map(row => ({
        ...row,
        id: row.id,
        type: "deposit",
        request_type: "deposit",
        reference:
          row.deposit_reference
      })),

      ...withdrawals.map(row => ({
        ...row,
        id: row.id,
        type: "withdrawal",
        request_type: "withdrawal",
        reference:
          row.withdrawal_reference
      })),

      ...transfers.map(row => ({
        ...row,
        id: row.id,
        type: "transfer",
        request_type: "transfer",
        reference:
          row.transfer_reference
      }))
    ];

    requests.sort(
      (a, b) =>
        new Date(
          b.created_at || 0
        ).getTime() -
        new Date(
          a.created_at || 0
        ).getTime()
    );

    return ok({
      requests:
        requests.slice(0, limit)
    });
  }


  /*
   * PATCH /api/admin/requests/:id
   */

  if (requestId) {

    const decision =
      String(
        body?.status || ""
      ).trim().toLowerCase();

    if (
      decision !== "approved" &&
      decision !== "rejected"
    ) {
      return bad(
        400,
        "Request status must be approved or rejected."
      );
    }

    /*
     * Find the pending request.
     * IDs are UUIDs, so we check each request table.
     */

    const depositRows =
      await sql`
        SELECT *
        FROM deposit_requests
        WHERE id = ${requestId}
          AND LOWER(
            COALESCE(status, 'pending')
          ) = 'pending'
        LIMIT 1
      `;

    if (depositRows.length) {

      const item =
        depositRows[0];

      if (decision === "rejected") {

        await sql`
          UPDATE deposit_requests
          SET
            status = 'rejected',
            reviewed_at = NOW(),
            reviewed_by = ${auth.user.id},
            updated_at = NOW()
          WHERE id = ${requestId}
        `;

        return ok({
          message:
            "Deposit request rejected.",
          request_type:
            "deposit",
          request:
            item
        });
      }

      const walletRows =
        await sql`
          SELECT *
          FROM wallets
          WHERE id = ${item.wallet_id}
            AND user_id = ${item.user_id}
          LIMIT 1
        `;

      if (!walletRows.length) {
        return bad(
          404,
          "Customer wallet could not be found."
        );
      }

      const wallet =
        walletRows[0];

      const amount =
        numberValue(
          item.amount,
          0
        );

      const before =
        numberValue(
          wallet.balance,
          0
        );

      const after =
        Number(
          (
            before + amount
          ).toFixed(2)
        );

      await sql`
        UPDATE wallets
        SET
          balance = ${after},
          updated_at = NOW()
        WHERE id = ${wallet.id}
      `;

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
            ${item.deposit_reference},
            'deposit',
            'credit',
            ${amount},
            0,
            ${item.currency || "USD"},
            'success',
            'Deposit approved by administrator.',
            ${JSON.stringify({
              source: "admin_request_approval",
              request_id: item.id
            })},
            NOW(),
            NOW()
          )
        `;

      } catch (error) {

        await sql`
          UPDATE wallets
          SET
            balance = ${before},
            updated_at = NOW()
          WHERE id = ${wallet.id}
        `;

        throw error;
      }

      await sql`
        UPDATE deposit_requests
        SET
          status = 'approved',
          reviewed_at = NOW(),
          reviewed_by = ${auth.user.id},
          updated_at = NOW()
        WHERE id = ${requestId}
      `;

      return ok({
        message:
          "Deposit request approved.",
        request_type:
          "deposit",
        amount,
        balance:
          after
      });
    }


    /*
     * WITHDRAWAL
     */

    const withdrawalRows =
      await sql`
        SELECT *
        FROM withdrawal_requests
        WHERE id = ${requestId}
          AND LOWER(
            COALESCE(status, 'pending')
          ) = 'pending'
        LIMIT 1
      `;

    if (withdrawalRows.length) {

      const item =
        withdrawalRows[0];

      if (decision === "rejected") {

        await sql`
          UPDATE withdrawal_requests
          SET
            status = 'rejected',
            reviewed_at = NOW(),
            reviewed_by = ${auth.user.id},
            updated_at = NOW()
          WHERE id = ${requestId}
        `;

        return ok({
          message:
            "Withdrawal request rejected.",
          request_type:
            "withdrawal",
          request:
            item
        });
      }

      const walletRows =
        await sql`
          SELECT *
          FROM wallets
          WHERE id = ${item.wallet_id}
            AND user_id = ${item.user_id}
          LIMIT 1
        `;

      if (!walletRows.length) {
        return bad(
          404,
          "Customer wallet could not be found."
        );
      }

      const wallet =
        walletRows[0];

      const amount =
        numberValue(
          item.amount,
          0
        );

      const before =
        numberValue(
          wallet.balance,
          0
        );

      if (before < amount) {
        return bad(
          400,
          "Customer no longer has enough balance to approve this withdrawal."
        );
      }

      const after =
        Number(
          (
            before - amount
          ).toFixed(2)
        );

      await sql`
        UPDATE wallets
        SET
          balance = ${after},
          updated_at = NOW()
        WHERE id = ${wallet.id}
      `;

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
            ${item.withdrawal_reference},
            'withdrawal',
            'debit',
            ${amount},
            ${numberValue(item.fee, 0)},
            ${item.currency || "USD"},
            'success',
            'Withdrawal approved by administrator.',
            ${JSON.stringify({
              source: "admin_request_approval",
              request_id: item.id
            })},
            NOW(),
            NOW()
          )
        `;

      } catch (error) {

        await sql`
          UPDATE wallets
          SET
            balance = ${before},
            updated_at = NOW()
          WHERE id = ${wallet.id}
        `;

        throw error;
      }

      await sql`
        UPDATE withdrawal_requests
        SET
          status = 'approved',
          reviewed_at = NOW(),
          reviewed_by = ${auth.user.id},
          processed_at = NOW(),
          updated_at = NOW()
        WHERE id = ${requestId}
      `;

      return ok({
        message:
          "Withdrawal request approved.",
        request_type:
          "withdrawal",
        amount,
        balance:
          after
      });
    }


    /*
     * TRANSFER
     */

    const transferRows =
      await sql`
        SELECT *
        FROM transfer_requests
        WHERE id = ${requestId}
          AND LOWER(
            COALESCE(status, 'pending')
          ) = 'pending'
        LIMIT 1
      `;

    if (transferRows.length) {

      const item =
        transferRows[0];

      if (decision === "rejected") {

        await sql`
          UPDATE transfer_requests
          SET
            status = 'rejected',
            admin_notes =
              COALESCE(
                admin_notes,
                'Rejected by administrator.'
              ),
            updated_at = NOW()
          WHERE id = ${requestId}
        `;

        return ok({
          message:
            "Transfer request rejected.",
          request_type:
            "transfer"
        });
      }

      const amount =
        numberValue(
          item.amount,
          0
        );

      if (amount <= 0) {
        return bad(
          400,
          "Transfer amount must be greater than zero."
        );
      }

      const senderRows =
        await sql`
          SELECT *
          FROM wallets
          WHERE id = ${item.sender_wallet_id}
            AND user_id = ${item.sender_user_id}
          LIMIT 1
        `;

      const recipientRows =
        await sql`
          SELECT *
          FROM wallets
          WHERE id = ${item.recipient_wallet_id}
            AND user_id = ${item.recipient_user_id}
          LIMIT 1
        `;

      if (
        !senderRows.length ||
        !recipientRows.length
      ) {
        return bad(
          404,
          "Transfer wallet could not be found."
        );
      }

      const sender =
        senderRows[0];

      const recipient =
        recipientRows[0];

      const senderBefore =
        numberValue(
          sender.balance,
          0
        );

      const recipientBefore =
        numberValue(
          recipient.balance,
          0
        );

      if (
        senderBefore < amount
      ) {
        return bad(
          400,
          "Sender no longer has enough balance for this transfer."
        );
      }

      const senderAfter =
        Number(
          (
            senderBefore - amount
          ).toFixed(2)
        );

      const recipientAfter =
        Number(
          (
            recipientBefore + amount
          ).toFixed(2)
        );

      await sql`
        UPDATE wallets
        SET
          balance = ${senderAfter},
          updated_at = NOW()
        WHERE id = ${sender.id}
      `;

      try {

        await sql`
          UPDATE wallets
          SET
            balance = ${recipientAfter},
            updated_at = NOW()
          WHERE id = ${recipient.id}
        `;

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
            ${item.sender_user_id},
            ${sender.id},
            ${item.transfer_reference},
            'transfer',
            'debit',
            ${amount},
            ${numberValue(item.fee, 0)},
            ${item.currency || "USD"},
            'success',
            'Transfer sent.',
            ${JSON.stringify({
              source: "admin_request_approval",
              request_id: item.id,
              recipient_user_id:
                item.recipient_user_id
            })},
            NOW(),
            NOW()
          )
        `;

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
            ${item.recipient_user_id},
            ${recipient.id},
            ${`${item.transfer_reference}-RECEIVE`},
            'transfer',
            'credit',
            ${amount},
            0,
            ${item.currency || "USD"},
            'success',
            'Transfer received.',
            ${JSON.stringify({
              source: "admin_request_approval",
              request_id: item.id,
              sender_user_id:
                item.sender_user_id
            })},
            NOW(),
            NOW()
          )
        `;

      } catch (error) {

        await sql`
          UPDATE wallets
          SET
            balance = ${senderBefore},
            updated_at = NOW()
          WHERE id = ${sender.id}
        `;

        await sql`
          UPDATE wallets
          SET
            balance = ${recipientBefore},
            updated_at = NOW()
          WHERE id = ${recipient.id}
        `;

        throw error;
      }

      await sql`
        UPDATE transfer_requests
        SET
          status = 'approved',
          processed_at = NOW(),
          updated_at = NOW()
        WHERE id = ${requestId}
      `;

      return ok({
        message:
          "Transfer request approved.",
        request_type:
          "transfer",
        amount
      });
    }

    return bad(
      404,
      "Request not found or has already been processed."
    );
  }

  return bad(
    400,
    "Invalid request."
  );
}


/* =====================================================
   ADMIN CHAT
===================================================== */

async function adminChat(
  request,
  body = null,
  conversationId = null
) {

  const auth =
    await requireAdmin(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }


  /*
   * GET /api/admin/chat
   * Return customer conversations.
   */

  if (
    !body &&
    !conversationId
  ) {

    const conversations =
      await sql`
        SELECT
          c.id,
          c.user_id,
          c.created_at,
          c.updated_at,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM chat_conversations c
        LEFT JOIN profiles p
          ON p.id = c.user_id
        ORDER BY
          c.updated_at DESC
      `;

    return ok({
      conversations
    });
  }


  /*
   * GET /api/admin/chat?conversation_id=...
   */

  if (
    !body &&
    conversationId
  ) {

    const conversations =
      await sql`
        SELECT *
        FROM chat_conversations
        WHERE id = ${conversationId}
        LIMIT 1
      `;

    if (!conversations.length) {
      return bad(
        404,
        "Conversation not found."
      );
    }

    const messages =
      await sql`
        SELECT *
        FROM chat_messages
        WHERE conversation_id =
          ${conversationId}
        ORDER BY created_at ASC
        LIMIT 500
      `;

    return ok({
      conversation:
        conversations[0],
      messages
    });
  }


  /*
   * POST /api/admin/chat/:conversation_id
   */

  if (
    body &&
    conversationId
  ) {

    const message =
      String(
        body.message ||
        body.content ||
        body.text ||
        ""
      ).trim();

    if (!message) {
      return bad(
        400,
        "Message is required."
      );
    }

    const conversations =
      await sql`
        SELECT *
        FROM chat_conversations
        WHERE id = ${conversationId}
        LIMIT 1
      `;

    if (!conversations.length) {
      return bad(
        404,
        "Conversation not found."
      );
    }

    const rows =
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
          ${crypto.randomUUID()},
          ${conversationId},
          ${auth.user.id},
          'admin',
          ${message},
          NOW()
        )
        RETURNING *
      `;

    await sql`
      UPDATE chat_conversations
      SET
        updated_at = NOW()
      WHERE id = ${conversationId}
    `;

    return ok({
      message:
        rows[0],
      messages:
        [rows[0]],
      message_text:
        "Message sent successfully."
    });
  }

  return bad(
    400,
    "Invalid chat request."
  );
     }
/* =====================================================
   CUSTOMER CHAT
===================================================== */

async function customerChat(request, body = null) {
  const auth = await requireCustomer(request);

  if (!auth.ok) {
    return bad(auth.status, auth.error, auth);
  }

  const userId = auth.user.id;

  let conversationRows = await sql`
    SELECT *
    FROM chat_conversations
    WHERE user_id = ${userId}
    ORDER BY updated_at DESC
    LIMIT 1
  `;

  let conversation;

  if (conversationRows.length) {
    conversation = conversationRows[0];
  } else {
    const rows = await sql`
      INSERT INTO chat_conversations (
        id,
        user_id,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${userId},
        NOW(),
        NOW()
      )
      RETURNING *
    `;

    conversation = rows[0];
  }

  if (!body) {
    const messages = await sql`
      SELECT *
      FROM chat_messages
      WHERE conversation_id = ${conversation.id}
      ORDER BY created_at ASC
      LIMIT 500
    `;

    return ok({
      conversation,
      messages
    });
  }

  const message = String(
    body.message ||
    body.content ||
    body.text ||
    ""
  ).trim();

  if (!message) {
    return bad(
      400,
      "Message is required."
    );
  }

  const rows = await sql`
    INSERT INTO chat_messages (
      id,
      conversation_id,
      sender_id,
      sender_type,
      message,
      created_at
    )
    VALUES (
      ${crypto.randomUUID()},
      ${conversation.id},
      ${userId},
      'customer',
      ${message},
      NOW()
    )
    RETURNING *
  `;

  await sql`
    UPDATE chat_conversations
    SET updated_at = NOW()
    WHERE id = ${conversation.id}
  `;

  return ok({
    conversation,
    message: rows[0],
    messages: [rows[0]],
    message_text:
      "Message sent successfully."
  });
}


/* =====================================================
   ADMIN CHAT
===================================================== */

async function adminChat(
  request,
  body = null,
  conversationId = null
) {
  const auth =
    await requireAdmin(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  if (body && conversationId) {
    const message = String(
      body.message ||
      body.content ||
      body.text ||
      ""
    ).trim();

    if (!message) {
      return bad(
        400,
        "Message is required."
      );
    }

    const customer = await sql`
      SELECT id
      FROM chat_conversations
      WHERE id = ${conversationId}
      LIMIT 1
    `;

    if (!customer.length) {
      return bad(
        404,
        "Conversation not found."
      );
    }

    const rows = await sql`
      INSERT INTO chat_messages (
        id,
        conversation_id,
        sender_id,
        sender_type,
        message,
        created_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${conversationId},
        ${auth.user.id},
        'admin',
        ${message},
        NOW()
      )
      RETURNING *
    `;

    await sql`
      UPDATE chat_conversations
      SET updated_at = NOW()
      WHERE id = ${conversationId}
    `;

    return ok({
      message: rows[0],
      messages: [rows[0]],
      message_text:
        "Message sent successfully."
    });
  }

  if (conversationId) {
    const conversations = await sql`
      SELECT
        c.*,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM chat_conversations c
      LEFT JOIN profiles p
        ON p.id = c.user_id
      WHERE c.id = ${conversationId}
      LIMIT 1
    `;

    if (!conversations.length) {
      return bad(
        404,
        "Conversation not found."
      );
    }

    const messages = await sql`
      SELECT *
      FROM chat_messages
      WHERE conversation_id =
        ${conversationId}
      ORDER BY created_at ASC
      LIMIT 500
    `;

    return ok({
      conversation:
        conversations[0],
      messages
    });
  }

  const conversations = await sql`
    SELECT
      c.id AS conversation_id,
      c.user_id,
      c.created_at,
      c.updated_at,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM chat_conversations c
    LEFT JOIN profiles p
      ON p.id = c.user_id
    ORDER BY c.updated_at DESC
    LIMIT 500
  `;

  return ok({
    conversations
  });
}


/* =====================================================
   ADMIN REQUESTS
===================================================== */

async function adminRequests(url) {
  const status =
    String(
      url.searchParams.get("status") ||
      ""
    ).trim().toLowerCase();

  const limit =
    cleanLimit(
      url.searchParams.get("limit"),
      500
    );

  const rows = await sql`
    SELECT
      d.id,
      d.deposit_reference AS reference,
      d.deposit_reference AS transaction_ref,
      d.user_id,
      d.amount,
      d.currency,
      d.status,
      d.created_at,
      'deposit' AS type,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM deposit_requests d
    LEFT JOIN profiles p
      ON p.id = d.user_id
    WHERE (
      ${status} = ''
      OR LOWER(
        COALESCE(d.status, 'pending')
      ) = ${status}
    )

    UNION ALL

    SELECT
      w.id,
      w.withdrawal_reference AS reference,
      w.withdrawal_reference AS transaction_ref,
      w.user_id,
      w.amount,
      w.currency,
      w.status,
      w.created_at,
      'withdrawal' AS type,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM withdrawal_requests w
    LEFT JOIN profiles p
      ON p.id = w.user_id
    WHERE (
      ${status} = ''
      OR LOWER(
        COALESCE(w.status, 'pending')
      ) = ${status}
    )

    UNION ALL

    SELECT
      t.id,
      t.transfer_reference AS reference,
      t.transfer_reference AS transaction_ref,
      t.sender_user_id AS user_id,
      t.amount,
      t.currency,
      t.status,
      t.created_at,
      'transfer' AS type,
      p.first_name,
      p.last_name,
      p.username,
      p.email
    FROM transfer_requests t
    LEFT JOIN profiles p
      ON p.id = t.sender_user_id
    WHERE (
      ${status} = ''
      OR LOWER(
        COALESCE(t.status, 'pending')
      ) = ${status}
    )

    ORDER BY created_at DESC
    LIMIT ${limit}
  `;

  return ok({
    requests: rows
  });
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
      WHERE LOWER(
        COALESCE(r.name, 'user')
      )
      NOT IN (
        'admin',
        'administrator'
      )
    `,

    sql`
      SELECT COUNT(*)::int AS count
      FROM profiles
      WHERE LOWER(
        COALESCE(
          kyc_status,
          'pending'
        )
      ) = 'pending'
    `,

    sql`
      SELECT COUNT(*)::int AS count
      FROM investments
    `,

    sql`
      SELECT COUNT(*)::int AS count
      FROM transactions
    `,

    /*
     * Do not assume pending_requests exists.
     */
    sql`
      SELECT (
        (
          SELECT COUNT(*)
          FROM deposit_requests
          WHERE LOWER(
            COALESCE(
              status,
              'pending'
            )
          ) = 'pending'
        )
        +
        (
          SELECT COUNT(*)
          FROM withdrawal_requests
          WHERE LOWER(
            COALESCE(
              status,
              'pending'
            )
          ) = 'pending'
        )
      )::int AS count
    `
  ]);

  return ok({
    stats: {
      customers:
        customers[0]?.count ||
        0,

      pending_kyc:
        pendingKyc[0]?.count ||
        0,

      investments:
        investments[0]?.count ||
        0,

      transactions:
        transactions[0]?.count ||
        0,

      pending_requests:
        pendingRequests[0]?.count ||
        0
    }
  });
}

/* =====================================================
   ADMIN CUSTOMERS
===================================================== */

async function adminCustomers(url) {
  const search =
    String(
      url.searchParams.get(
        "search"
      ) || ""
    ).trim();

  const limit =
    cleanLimit(
      url.searchParams.get(
        "limit"
      ),
      100
    );

  const offset =
    Math.max(
      Number(
        url.searchParams.get(
          "offset"
        ) || 0
      ),
      0
    );

  const rows =
    await sql`
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
      WHERE LOWER(
        COALESCE(
          r.name,
          'user'
        )
      )
      NOT IN (
        'admin',
        'administrator'
      )
      AND (
        ${search} = ''
        OR LOWER(
          COALESCE(
            p.first_name,
            ''
          )
        ) LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.last_name,
            ''
          )
        ) LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.username,
            ''
          )
        ) LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.email,
            ''
          )
        ) LIKE LOWER(
          ${"%" + search + "%"}
        )
      )
      ORDER BY
        p.created_at DESC
      LIMIT ${limit}
      OFFSET ${offset}
    `;

  return ok({
    customers:
      rows
  });
}

async function adminCustomer(id) {
  if (!id) {
    return bad(
      400,
      "Customer ID is required."
    );
  }

  const result =
    await sql`
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
    customer:
      result[0]
  });
}

/* =====================================================
   ADMIN WALLETS
===================================================== */

async function adminWallets(url) {
  const search =
    String(
      url.searchParams.get(
        "search"
      ) || ""
    ).trim();

  const limit =
    cleanLimit(
      url.searchParams.get(
        "limit"
      ),
      100
    );

  await ensureAllCustomerWallets();

  const customers =
    await sql`
      SELECT
        p.id AS user_id,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM profiles p
      LEFT JOIN roles r
        ON r.id = p.role_id
      WHERE LOWER(
        COALESCE(
          r.name,
          'user'
        )
      )
      NOT IN (
        'admin',
        'administrator'
      )
      AND (
        ${search} = ''
        OR LOWER(
          COALESCE(
            p.username,
            ''
          )
        ) LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.email,
            ''
          )
        ) LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.first_name ||
            ' ' ||
            p.last_name,
            ''
          )
        ) LIKE LOWER(
          ${"%" + search + "%"}
        )
      )
      ORDER BY
        p.created_at DESC
      LIMIT ${limit}
    `;

  const result = [];

  for (const customer of customers) {
    let walletRows = [];

    try {
      walletRows =
        await sql`
          SELECT *
          FROM wallets
          WHERE user_id =
            ${customer.user_id}
          ORDER BY
            created_at ASC
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
          wallet.wallet_type ||
          ""
        ).toLowerCase();

      if (
        type === "main"
      ) {
        main = wallet;
      }

      if (
        type === "profit"
      ) {
        profit = wallet;
      }
    }

    if (
      !main &&
      walletRows.length
    ) {
      const legacy =
        walletRows[0];

      if (
        legacy.main_balance !==
          undefined ||
        legacy.profit_balance !==
          undefined
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
        main?.id ||
        null,

      profit_wallet_id:
        profit?.id ||
        null,

      main_balance:
        main?.balance !==
        undefined
          ? numberValue(
              main.balance
            )
          : numberValue(
              main?.main_balance,
              0
            ),

      profit_balance:
        profit?.balance !==
        undefined
          ? numberValue(
              profit.balance
            )
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
    wallets:
      result
  });
}

/* =====================================================
   ADMIN SINGLE CUSTOMER WALLET
===================================================== */

async function adminWallet(
  userId
) {
  if (!userId) {
    return bad(
      400,
      "User ID is required."
    );
  }

  await ensureUserWallets(
    userId
  );

  const profile =
    await sql`
      SELECT
        p.id,
        p.first_name,
        p.last_name,
        p.username,
        p.email
      FROM profiles p
      WHERE p.id =
        ${userId}
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
    wallets =
      await sql`
        SELECT *
        FROM wallets
        WHERE user_id =
          ${userId}
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
    ledger =
      await sql`
        SELECT *
        FROM wallet_ledger
        WHERE user_id =
          ${userId}
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
    await requireAdmin(
      request
    );

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
    numberValue(
      body.amount,
      NaN
    );

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

  const customer =
    await sql`
      SELECT id
      FROM profiles
      WHERE id =
        ${userId}
      LIMIT 1
    `;

  if (!customer.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  await ensureUserWallets(
    userId
  );

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${userId}
        AND wallet_type =
          ${walletType}
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      404,
      "Customer wallet not found."
    );
  }

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

  const transactionReference =
    `ADJ-${crypto.randomUUID()}`;

  /*
   * Update the exact wallet record that the
   * customer dashboard reads.
   */
  const updated =
    await sql`
      UPDATE wallets
      SET
        balance = ${next},
        updated_at = NOW()
      WHERE id =
        ${wallet.id}
      RETURNING *
    `;

  /*
   * Ledger record.
   */
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
    console.error(
      "ADMIN WALLET LEDGER INSERT FAILED:",
      error?.message ||
        error
    );

    /*
     * Do not leave a wallet changed without
     * its corresponding ledger entry.
     */
    await sql`
      UPDATE wallets
      SET
        balance =
          ${current},
        updated_at =
          NOW()
      WHERE id =
        ${wallet.id}
    `;

    return bad(
      500,
      "Wallet was not updated because the wallet ledger could not be created.",
      {
        detail:
          error?.message
      }
    );
  }

  /*
   * Transaction record.
   */
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
        ${userId},
        ${wallet.id},
        ${transactionReference},
        ${
          amount >= 0
            ? "system_credit"
            : "system_debit"
        },
        ${
          amount >= 0
            ? "credit"
            : "debit"
        },
        ${Math.abs(amount)},
        0,
        'USD',
        'success',
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
    console.error(
      "ADMIN WALLET TRANSACTION INSERT FAILED:",
      error?.message ||
        error
    );

    await sql`
      UPDATE wallets
      SET
        balance =
          ${current},
        updated_at =
          NOW()
      WHERE id =
        ${wallet.id}
    `;

    return bad(
      500,
      "Wallet was not updated because the transaction record could not be created.",
      {
        detail:
          error?.message
      }
    );
  }

  return ok({
    message:
      "Wallet balance updated successfully.",

    wallet:
      updated[0],

    transaction_reference:
      transactionReference
  });
}

/* =====================================================
   ADMIN KYC
===================================================== */

async function adminKyc(url) {
  const status =
    String(
      url.searchParams.get(
        "status"
      ) || ""
    )
      .trim()
      .toLowerCase();

  const limit =
    cleanLimit(
      url.searchParams.get(
        "limit"
      ),
      100
    );

  let rows = [];

  try {
    if (status) {
      rows =
        await sql`
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
          WHERE LOWER(
            COALESCE(
              k.status,
              'pending'
            )
          ) = ${status}
          ORDER BY
            k.created_at DESC
          LIMIT ${limit}
        `;
    } else {
      rows =
        await sql`
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
          ORDER BY
            k.created_at DESC
          LIMIT ${limit}
        `;
    }
  } catch (error) {
    /*
     * Important:
     * Customers can be KYC-approved by admin even when
     * they never submitted a KYC record.
     *
     * Therefore the profile itself remains the source
     * of truth for this compatibility path.
     */
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
        WHERE LOWER(
          COALESCE(
            r.name,
            'user'
          )
        )
        NOT IN (
          'admin',
          'administrator'
        )
        AND (
          ${status} = ''
          OR LOWER(
            COALESCE(
              p.kyc_status,
              'pending'
            )
          ) = ${status}
        )
        ORDER BY
          p.created_at DESC
        LIMIT ${limit}
      `;

    rows =
      profileRows;
  }

  /*
   * If there are no submissions, still expose profile
   * KYC status so admin can approve a customer who
   * never submitted an application.
   */
  if (!rows.length) {
    rows =
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
        WHERE LOWER(
          COALESCE(
            r.name,
            'user'
          )
        )
        NOT IN (
          'admin',
          'administrator'
        )
        AND (
          ${status} = ''
          OR LOWER(
            COALESCE(
              p.kyc_status,
              'pending'
            )
          ) = ${status}
        )
        ORDER BY
          p.created_at DESC
        LIMIT ${limit}
      `;
  }

  return ok({
    submissions:
      rows
  });
}

/* =====================================================
   ADMIN REVIEW KYC
===================================================== */

async function reviewKyc(
  request,
  id,
  body
) {
  const admin =
    await requireAdmin(
      request
    );

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

  if (!id) {
    return bad(
      400,
      "KYC/customer ID is required."
    );
  }

  let submission = [];

  try {
    submission =
      await sql`
        SELECT *
        FROM kyc_submissions
        WHERE id =
          ${id}
        LIMIT 1
      `;
  } catch {
    submission = [];
  }

  /*
   * No submission exists.
   * Treat the supplied ID as a customer/profile ID.
   */
  if (!submission.length) {
    const profile =
      await sql`
        SELECT id
        FROM profiles
        WHERE id =
          ${id}
        LIMIT 1
      `;

    if (!profile.length) {
      return bad(
        404,
        "KYC/customer record not found."
      );
    }

    /*
     * THIS is the important synchronization fix:
     *
     * Admin approval directly updates profiles.kyc_status.
     */
    await sql`
      UPDATE profiles
      SET
        kyc_status =
          ${decision},
        updated_at =
          NOW()
      WHERE id =
        ${id}
    `;

    return ok({
      message:
        `KYC ${decision} successfully.`,

      submission: {
        id,
        user_id: id,
        status:
          decision
      }
    });
  }

  const userId =
    submission[0].user_id;

  const updated =
    await sql`
      UPDATE kyc_submissions
      SET
        status =
          ${decision},

        reviewed_by =
          ${admin.user.id},

        reviewed_at =
          NOW(),

        updated_at =
          NOW()

      WHERE id =
        ${id}

      RETURNING *
    `;

  /*
   * Synchronize the profile.
   */
  await sql`
    UPDATE profiles
    SET
      kyc_status =
        ${decision},
      updated_at =
        NOW()
    WHERE id =
      ${userId}
  `;

  return ok({
    message:
      `KYC ${decision} successfully.`,

    submission:
      updated[0]
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
    await requireAdmin(
      request
    );

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

  const currentProfile =
    await sql`
      SELECT
        id,
        status,
        email_verified_at,
        kyc_status
      FROM profiles
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (!currentProfile.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  const firstName =
    body.first_name !==
    undefined
      ? String(
          body.first_name
        ).trim()
      : null;

  const lastName =
    body.last_name !==
    undefined
      ? String(
          body.last_name
        ).trim()
      : null;

  const username =
    body.username !==
    undefined
      ? String(
          body.username
        ).trim()
      : null;

  const status =
    body.status !==
    undefined
      ? String(
          body.status
        ).trim()
      : null;

  const kycStatus =
    body.kyc_status !==
    undefined
      ? String(
          body.kyc_status
        ).trim()
        .toLowerCase()
      : null;

  const currentStatus =
    currentProfile[0].status;

  const nextStatus =
    status !== null
      ? status
      : currentStatus;

  const approvalChanged =
    isApprovedStatus(
      nextStatus
    );

  /*
   * ADMIN ACCOUNT APPROVAL = EMAIL VERIFICATION
   *
   * This intentionally does NOT depend on Resend.
   */
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

        email_verified_at =
          CASE
            WHEN ${approvalChanged}
              THEN COALESCE(
                email_verified_at,
                NOW()
              )

            ELSE
              email_verified_at
          END,

        updated_at =
          NOW()

      WHERE id =
        ${id}

      RETURNING *
    `;

  await ensureUserWallets(
    id
  );

  return ok({
    message:
      "Customer updated successfully.",

    customer:
      updated[0]
  });
}

/* =====================================================
   EMAIL VERIFICATION
===================================================== */

async function verifyEmail(
  token
) {
  const cleanToken =
    String(
      token || ""
    ).trim();

  if (!cleanToken) {
    return bad(
      400,
      "Verification token is required."
    );
  }

  const tokenHash =
    hashToken(
      cleanToken
    );

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
        AND t.expires_at >
          NOW()
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
      updated_at =
        NOW()
    WHERE id =
      ${item.user_id}
  `;

  await sql`
    UPDATE auth_email_tokens
    SET
      used_at =
        NOW()
    WHERE id =
      ${item.token_id}
  `;

  return ok({
    message:
      "Your email has been confirmed successfully."
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
    resetKey !==
      configuredKey
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

  if (
    !email ||
    !password
  ) {
    return bad(
      400,
      "Email and password are required."
    );
  }

  if (
    password.length < 6
  ) {
    return bad(
      400,
      "Password must contain at least 6 characters."
    );
  }

  const passwordHash =
    hashPassword(
      password
    );

  const result =
    await sql`
      UPDATE auth_credentials
      SET
        password_hash =
          ${passwordHash},

        password_updated_at =
          NOW(),

        failed_login_attempts =
          0,

        locked_until =
          NULL,

        updated_at =
          NOW()

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
    String(
      req.url || "/"
    );

  const absoluteUrl =
    rawUrl.startsWith(
      "http://"
    ) ||
    rawUrl.startsWith(
      "https://"
    )
      ? rawUrl
      : `${protocol}://${host}${rawUrl}`;

  const requestHeaders =
    new Headers();

  for (
    const [
      key,
      value
    ] of Object.entries(
      req.headers || {}
    )
  ) {
    if (
      Array.isArray(value)
    ) {
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
        typeof req.body ===
        "string"
      ) {
        body =
          req.body;
      } else if (
        Buffer.isBuffer(
          req.body
        )
      ) {
        body =
          req.body;
      } else {
        body =
          JSON.stringify(
            req.body
          );

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
        req.method ||
        "GET",

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
  if (res.headersSent)
    return;

  res.statusCode =
    webResponse.status;

  webResponse.headers.forEach(
    (
      value,
      key
    ) => {
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
      createWebRequest(
        req
      );

    if (
      request.method ===
      "OPTIONS"
    ) {
      res.statusCode =
        204;

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
      new URL(
        request.url
      );

    const path =
      url.pathname;

    const method =
      request.method.toUpperCase();

    /* =================================================
       HEALTH
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/health"
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
      path ===
        "/api/auth/register"
    ) {
      return writeWebResponse(
        res,
        await register(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       AUTH LOGIN
    ================================================= */

    if (
      method === "POST" &&
      path ===
        "/api/auth/login"
    ) {
      return writeWebResponse(
        res,
        await login(
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       AUTH VERIFY EMAIL
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/auth/verify-email"
    ) {
      return writeWebResponse(
        res,
        await verifyEmail(
          url.searchParams.get(
            "token"
          )
        )
      );
    }

    /* =================================================
       AUTH LOGOUT
    ================================================= */

    if (
      method === "POST" &&
      path ===
        "/api/auth/logout"
    ) {
      return writeWebResponse(
        res,
        await logout(
          request
        )
      );
    }

    /* =================================================
       AUTH ME
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/auth/me"
    ) {
      return writeWebResponse(
        res,
        await me(
          request
        )
      );
    }

    /* =================================================
       CUSTOMER DASHBOARD
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/dashboard" ||
        path ===
          "/api/customer/me/dashboard" ||
        path ===
          "/api/user/dashboard" ||
        path ===
          "/api/dashboard"
      )
    ) {
      return writeWebResponse(
        res,
        await customerDashboard(
          request
        )
      );
    }

    /* =================================================
       CUSTOMER WALLETS
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/wallets" ||
        path ===
          "/api/customer/wallet" ||
        path ===
          "/api/user/wallets" ||
        path ===
          "/api/wallets"
      )
    ) {
      return writeWebResponse(
        res,
        await customerWallets(
          request
        )
      );
    }

    /* =================================================
       CUSTOMER TRANSACTIONS
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/transactions" ||
        path ===
          "/api/customer/transaction-history" ||
        path ===
          "/api/user/transactions" ||
        path ===
          "/api/transactions"
      )
    ) {
      return writeWebResponse(
        res,
        await customerTransactions(
          request,
          url
        )
      );
    }

    /* =================================================
       CUSTOMER PROFILE
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/profile" ||
        path ===
          "/api/user/profile" ||
        path ===
          "/api/profile"
      )
    ) {
      return writeWebResponse(
        res,
        await customerProfile(
          request
        )
      );
    }

    if (
      (
        method === "PUT" ||
        method === "PATCH" ||
        method === "POST"
      ) &&
      (
        path ===
          "/api/customer/profile" ||
        path ===
          "/api/user/profile" ||
        path ===
          "/api/profile"
      )
    ) {
      return writeWebResponse(
        res,
        await customerProfile(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER KYC
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/kyc" ||
        path ===
          "/api/user/kyc" ||
        path ===
          "/api/kyc"
      )
    ) {
      return writeWebResponse(
        res,
        await customerKyc(
          request
        )
      );
    }

    if (
      method === "POST" &&
      (
        path ===
          "/api/customer/kyc" ||
        path ===
          "/api/user/kyc" ||
        path ===
          "/api/kyc" ||
        path ===
          "/api/kyc/apply"
      )
    ) {
      return writeWebResponse(
        res,
        await customerKyc(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER DEPOSIT
    ================================================= */

    if (
      method === "POST" &&
      (
        path ===
          "/api/customer/deposit" ||
        path ===
          "/api/user/deposit" ||
        path ===
          "/api/deposit"
      )
    ) {
      return writeWebResponse(
        res,
        await customerDeposit(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER SEND
    ================================================= */

    if (
      method === "POST" &&
      (
        path ===
          "/api/customer/send" ||
        path ===
          "/api/user/send" ||
        path ===
          "/api/send" ||
        path ===
          "/api/send-money"
      )
    ) {
      return writeWebResponse(
        res,
        await customerSend(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER WITHDRAWAL ACCOUNT
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/withdrawal-account" ||
        path ===
          "/api/user/withdrawal-account" ||
        path ===
          "/api/withdrawal-account"
      )
    ) {
      return writeWebResponse(
        res,
        await customerWithdrawalAccount(
          request
        )
      );
    }

    if (
      (
        method === "POST" ||
        method === "PUT" ||
        method === "PATCH"
      ) &&
      (
        path ===
          "/api/customer/withdrawal-account" ||
        path ===
          "/api/user/withdrawal-account" ||
        path ===
          "/api/withdrawal-account"
      )
    ) {
      return writeWebResponse(
        res,
        await customerWithdrawalAccount(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER WITHDRAW
    ================================================= */

    if (
      method === "POST" &&
      (
        path ===
          "/api/customer/withdraw" ||
        path ===
          "/api/user/withdraw" ||
        path ===
          "/api/withdraw" ||
        path ===
          "/api/withdrawal"
      )
    ) {
      return writeWebResponse(
        res,
        await customerWithdraw(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER INVESTMENTS
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/investments" ||
        path ===
          "/api/user/investments" ||
        path ===
          "/api/investments"
      )
    ) {
      return writeWebResponse(
        res,
        await customerInvestments(
          request,
          url
        )
      );
    }

    /* =================================================
       ADMIN PASSWORD RESET
    ================================================= */

    if (
      method === "POST" &&
      path ===
        "/api/admin/reset-password"
    ) {
      return writeWebResponse(
        res,
        await resetAdminPassword(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       ADMIN DASHBOARD
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/admin/dashboard" ||
        path ===
          "/api/admin/stats"
      )
    ) {
      const auth =
        await requireAdmin(
          request
        );

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
       ADMIN CUSTOMERS
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/admin/customers"
    ) {
      const auth =
        await requireAdmin(
          request
        );

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
        url.searchParams.get(
          "id"
        );

      if (id) {
        return writeWebResponse(
          res,
          await adminCustomer(
            id
          )
        );
      }

      return writeWebResponse(
        res,
        await adminCustomers(
          url
        )
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
      const auth =
        await requireAdmin(
          request
        );

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
        path.split(
          "/"
        ).pop();

      return writeWebResponse(
        res,
        await updateCustomer(
          request,
          id,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       ADMIN WALLETS
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/admin/wallets" ||
        path ===
          "/api/admin/wallet"
      )
    ) {
      const auth =
        await requireAdmin(
          request
        );

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
          await adminWallet(
            userId
          )
        );
      }

      return writeWebResponse(
        res,
        await adminWallets(
          url
        )
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
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       ADMIN KYC
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/admin/kyc"
    ) {
      const auth =
        await requireAdmin(
          request
        );

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
        await adminKyc(
          url
        )
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
        path.split(
          "/"
        ).pop();

      return writeWebResponse(
        res,
        await reviewKyc(
          request,
          id,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       ADMIN INVESTMENTS
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/admin/investments"
    ) {
      const auth =
        await requireAdmin(
          request
        );

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(
            auth.status,
            auth.error
          )
        );
      }

      const limit =
        cleanLimit(
          url.searchParams.get(
            "limit"
          ),
          100
        );

      const rows =
        await sql`
          SELECT
            i.*,
            p.first_name,
            p.last_name,
            p.username,
            p.email
          FROM investments i
          INNER JOIN profiles p
            ON p.id = i.user_id
          ORDER BY
            i.created_at DESC
          LIMIT ${limit}
        `;

      return writeWebResponse(
        res,
        ok({
          investments:
            rows
        })
      );
    }

    /* =================================================
       ADMIN TRANSACTIONS
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/admin/transactions"
    ) {
      const auth =
        await requireAdmin(
          request
        );

      if (!auth.ok) {
        return writeWebResponse(
          res,
          bad(
            auth.status,
            auth.error
          )
        );
      }

      const limit =
        cleanLimit(
          url.searchParams.get(
            "limit"
          ),
          100
        );

      let rows = [];

      try {
        rows =
          await sql`
            SELECT
              t.*,
              p.first_name,
              p.last_name,
              p.username,
              p.email
            FROM transactions t
            LEFT JOIN profiles p
              ON p.id =
                t.user_id
            ORDER BY
              t.created_at DESC
            LIMIT ${limit}
          `;
      } catch (error) {
        console.warn(
          "Admin transaction query failed:",
          error?.message
        );
      }

      return writeWebResponse(
        res,
        ok({
          transactions:
            rows
        })
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

    if (
      res.headersSent
    ) {
      res.end();
      return;
    }

    return writeWebResponse(
      res,
      response(
        500,
        {
          success: false,
          error:
            error?.message ||
            "Internal server error."
        }
      )
    );
  }
}
