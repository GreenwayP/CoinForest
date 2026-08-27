/* COMPLETE UPDATED INDEX.JS
   CoinForest — Customer Dashboard / Admin API
   Updated from the current 5,316-line source.
   Includes:
   - Admin approval => email verified
   - Customer KYC application + admin KYC approval sync
   - Customer/admin wallet synchronization
   - Customer transaction history
   - Deposit / send / withdrawal handling
   - Withdrawal account storage
   - Customer/admin chat
   - Admin activity
   - Existing authentication and routes preserved
*/

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
   * Email verification is intentionally NOT a barrier.
   * Administrator approval is the current verification
   * mechanism until the official Resend domain is ready.
   */
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
  }

  return response(201, {
    success: true,
    email_sent: false,
    message:
      "Account created. Your account is awaiting administrator approval. Administrator approval will verify the account.",
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
    SELECT p.id
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

  /*
   * Administrator approval is the temporary email
   * verification mechanism.
   */
  const approved =
    ["active", "approved"].includes(
      String(user.status || "")
        .trim()
        .toLowerCase()
    );

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
      kyc_status: user.kyc_status,
      email_verified:
        !!user.email_verified_at ||
        approved
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

async function requireCustomer(request) {
  const auth =
    await authenticate(request);

  if (!auth.ok) return auth;

  const role =
    String(
      auth.user.role_name || ""
    ).toLowerCase();

  if (
    role === "admin" ||
    role === "administrator"
  ) {
    return {
      ok: false,
      status: 403,
      error:
        "Customer access required."
    };
  }

  return auth;
}

function customerIsApproved(user) {
  return [
    "active",
    "approved"
  ].includes(
    String(user?.status || "")
      .trim()
      .toLowerCase()
  );
}

async function requireApprovedCustomer(request) {
  const auth =
    await requireCustomer(request);

  if (!auth.ok) return auth;

  if (!customerIsApproved(auth.user)) {
    return {
      ok: false,
      status: 403,
      error:
        "Your account is awaiting administrator approval. Please wait until your account is approved before performing this action.",
      code:
        "ACCOUNT_NOT_APPROVED",
      account_approved: false
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

  const approved =
    customerIsApproved(user);

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
      email_verified:
        !!user.email_verified_at ||
        approved,
      email_verified_at:
        user.email_verified_at ||
        (
          approved
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
   CUSTOMER WALLET STATE
===================================================== */

async function loadCustomerWalletState(userId) {
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
      )
        .trim()
        .toLowerCase();

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

  const mainBalance =
    (
      typedMainBalance !== 0 ||
      !legacy
    )
      ? typedMainBalance
      : legacyMainBalance;

  const profitBalance =
    (
      typedProfitBalance !== 0 ||
      !legacy
    )
      ? typedProfitBalance
      : legacyProfitBalance;

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

  return {
    rows,
    main,
    profit,
    legacy,
    mainBalance,
    profitBalance,
    totalBalance:
      mainBalance +
      profitBalance
  };
}

async function getCustomerMainWallet(userId) {
  const state =
    await loadCustomerWalletState(
      userId
    );

  if (state.main) {
    const typedBalance =
      state.main.balance !==
      undefined
        ? numberValue(
            state.main.balance,
            0
          )
        : null;

    const isLegacy =
      state.main.main_balance !==
        undefined &&
      state.main.wallet_type ===
        undefined;

    if (
      !isLegacy &&
      typedBalance !== null
    ) {
      if (
        typedBalance !== 0 ||
        !state.legacy ||
        numberValue(
          state.legacy.main_balance,
          0
        ) === 0
      ) {
        return {
          wallet: state.main,
          balance: typedBalance,
          legacy: false,
          state
        };
      }
    }
  }

  if (
    state.legacy &&
    state.legacy.main_balance !==
      undefined
  ) {
    return {
      wallet: state.legacy,
      balance:
        numberValue(
          state.legacy.main_balance,
          0
        ),
      legacy: true,
      state
    };
  }

  if (state.main) {
    return {
      wallet: state.main,
      balance:
        numberValue(
          state.main.balance,
          0
        ),
      legacy: false,
      state
    };
  }

  return {
    wallet: null,
    balance: 0,
    legacy: false,
    state
  };
}

async function setCustomerMainWalletBalance(
  wallet,
  nextBalance,
  legacy = false
) {
  if (!wallet) {
    throw new Error(
      "Main wallet could not be found."
    );
  }

  if (
    legacy ||
    (
      wallet.main_balance !==
        undefined &&
      wallet.wallet_type ===
        undefined
    )
  ) {
    const rows = await sql`
      UPDATE wallets
      SET
        main_balance =
          ${nextBalance},
        updated_at = NOW()
      WHERE id = ${wallet.id}
      RETURNING *
    `;

    return rows[0];
  }

  const rows = await sql`
    UPDATE wallets
    SET
      balance = ${nextBalance},
      updated_at = NOW()
    WHERE id = ${wallet.id}
    RETURNING *
  `;

  return rows[0];
}

/* =====================================================
   CUSTOMER WALLETS
===================================================== */

async function customerWallets(request) {
  const auth =
    await requireCustomer(request);

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
      main_wallet: state.main,
      profit_wallet:
        state.profit,
      main_balance:
        state.mainBalance,
      profit_balance:
        state.profitBalance,
      total_balance:
        state.totalBalance,
      account_approved:
        customerIsApproved(
          auth.user
        )
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

  try {
    const ledger =
      await sql`
        SELECT *
        FROM wallet_ledger
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
        LIMIT ${limit}
      `;

    const existingIds =
      new Set(
        rows.map(
          item =>
            String(
              item.id || ""
            )
        )
      );

    for (const item of ledger) {
      if (
        existingIds.has(
          String(item.id || "")
        )
      ) {
        continue;
      }

      rows.push({
        ...item,
        id: item.id,
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
          "completed",
        description:
          item.description ||
          "Wallet activity",
        metadata:
          item.metadata || {
            source:
              "wallet_ledger"
          }
      });
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

async function customerDashboard(request) {
  const auth =
    await requireCustomer(request);

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
        "Customer investments query warning:",
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
      customerIsApproved(
        profile
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
      portfolio:
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

async function customerTransactions(
  request,
  url
) {
  const auth =
    await requireCustomer(request);

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
      auth.error
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
    await requireCustomer(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
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
    profileRows[0];

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
        String(
          profile?.kyc_status ||
            "pending"
        ).toLowerCase(),
      profile,
      submissions
    });
  }

  if (
    !customerIsApproved(
      auth.user
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

  const current =
    String(
      profile?.kyc_status ||
        "pending"
    ).toLowerCase();

  if (
    current === "approved"
  ) {
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
    console.warn(
      "KYC pending lookup warning:",
      error?.message
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

function kycRequired(user) {
  return String(
    user?.kyc_status ||
      "pending"
  ).toLowerCase() !==
    "approved";
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

  const walletInfo =
    await getCustomerMainWallet(
      auth.user.id
    );

  if (!walletInfo.wallet) {
    return bad(
      500,
      "Main wallet could not be found."
    );
  }

  const reference =
    String(
      body.deposit_reference ||
        body.payment_reference ||
        `DEP-${crypto.randomUUID()}`
    ).trim();

  const paymentMethod =
    String(
      body.payment_method ||
        body.method ||
        "Bank Transfer"
    ).trim();

  const proofUrl =
    body.proof_url
      ? String(
          body.proof_url
        )
      : null;

  const currency =
    String(
      body.currency ||
        "USD"
    )
      .trim()
      .toUpperCase();

  const id =
    crypto.randomUUID();

  try {
    const rows =
      await sql`
        INSERT INTO deposit_requests (
          id,
          user_id,
          wallet_id,
          deposit_reference,
          amount,
          currency,
          payment_method,
          proof_url,
          status,
          submitted_at,
          created_at,
          updated_at
        )
        VALUES (
          ${id},
          ${auth.user.id},
          ${walletInfo.wallet.id},
          ${reference},
          ${amount},
          ${currency},
          ${paymentMethod},
          ${proofUrl},
          'pending',
          NOW(),
          NOW(),
          NOW()
        )
        RETURNING *
      `;

    return ok({
      message:
        "Deposit request submitted successfully.",
      request:
        rows[0],
      deposit:
        rows[0]
    });
  } catch (error) {
    console.error(
      "Customer deposit error:",
      error
    );

    return bad(
      500,
      "Deposit request could not be submitted.",
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
      auth.error
    );
  }

  if (
    kycRequired(
      auth.user
    )
  ) {
    return bad(
      403,
      "KYC verification is required before sending money.",
      {
        code:
          "KYC_REQUIRED",
        kyc_required:
          true
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

  const recipientEmail =
    normalizeEmail(
      body.recipient_email ||
        body.email ||
        body.recipient
    );

  const recipientUsername =
    String(
      body.recipient_username ||
        body.username ||
        ""
    ).trim();

  if (
    !recipientEmail &&
    !recipientUsername
  ) {
    return bad(
      400,
      "Recipient email or username is required."
    );
  }

  const recipientRows =
    await sql`
      SELECT
        p.id,
        p.email,
        p.username,
        p.first_name,
        p.last_name
      FROM profiles p
      WHERE
        (
          ${recipientEmail || null}
            IS NOT NULL
          AND LOWER(p.email) =
            ${recipientEmail}
        )
        OR
        (
          ${recipientUsername || null}
            IS NOT NULL
          AND LOWER(p.username) =
            LOWER(${recipientUsername})
        )
      LIMIT 1
    `;

  if (!recipientRows.length) {
    return bad(
      404,
      "Recipient account not found."
    );
  }

  const recipient =
    recipientRows[0];

  if (
    recipient.id ===
    auth.user.id
  ) {
    return bad(
      400,
      "You cannot send money to yourself."
    );
  }

  const senderInfo =
    await getCustomerMainWallet(
      auth.user.id
    );

  const receiverInfo =
    await getCustomerMainWallet(
      recipient.id
    );

  if (
    !senderInfo.wallet ||
    !receiverInfo.wallet
  ) {
    return bad(
      500,
      "Main wallet could not be found."
    );
  }

  const sender =
    senderInfo.wallet;

  const receiver =
    receiverInfo.wallet;

  const senderBalance =
    senderInfo.balance;

  const receiverBalance =
    receiverInfo.balance;

  if (
    senderBalance < amount
  ) {
    return bad(
      400,
      "Insufficient Main Wallet balance."
    );
  }

  const senderNext =
    senderBalance -
    amount;

  const receiverNext =
    receiverBalance +
    amount;

  const reference =
    `SND-${crypto.randomUUID()}`;

  await setCustomerMainWalletBalance(
    sender,
    senderNext,
    senderInfo.legacy
  );

  try {
    await setCustomerMainWalletBalance(
      receiver,
      receiverNext,
      receiverInfo.legacy
    );

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
        ${sender.id},
        ${reference},
        'transfer',
        'debit',
        ${amount},
        0,
        'USD',
        'completed',
        'Money sent',
        ${JSON.stringify({
          recipient_id:
            recipient.id,
          recipient_email:
            recipient.email
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
        ${recipient.id},
        ${receiver.id},
        ${reference}-R,
        'transfer',
        'credit',
        ${amount},
        0,
        'USD',
        'completed',
        'Money received',
        ${JSON.stringify({
          sender_id:
            auth.user.id,
          sender_email:
            auth.user.email
        })},
        NOW(),
        NOW()
      )
    `;
  } catch (error) {
    await setCustomerMainWalletBalance(
      sender,
      senderBalance,
      senderInfo.legacy
    );

    await setCustomerMainWalletBalance(
      receiver,
      receiverBalance,
      receiverInfo.legacy
    );

    return bad(
      500,
      "Send failed and the wallet balances were restored.",
      {
        detail:
          error?.message
      }
    );
  }

  return ok({
    message:
      "Money sent successfully.",
    reference,
    amount,
    recipient
  });
}

/* =====================================================
   WITHDRAWAL ACCOUNT
===================================================== */

async function ensureWithdrawalAccountSchema() {
  await sql`
    CREATE TABLE IF NOT EXISTS withdrawal_accounts (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL UNIQUE
        REFERENCES profiles(id)
        ON DELETE CASCADE,
      method_name TEXT NOT NULL
        DEFAULT 'Bank Transfer',
      account_name TEXT NOT NULL,
      account_number TEXT NOT NULL,
      bank_name TEXT NOT NULL,
      swift_code TEXT,
      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `;

  await sql`
    ALTER TABLE withdrawal_requests
    ADD COLUMN IF NOT EXISTS
      withdrawal_account_id UUID
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
      auth.error
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
        rows[0] || null,
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
          updated_at = NOW()
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
    await requireCustomer(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  if (
    !customerIsApproved(
      auth.user
    )
  ) {
    return bad(
      403,
      "Your account is awaiting administrator approval.",
      {
        code:
          "ACCOUNT_NOT_APPROVED"
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
        kyc_required:
          true
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
        requires_withdrawal_account:
          true
      }
    );
  }

  const walletInfo =
    await getCustomerMainWallet(
      auth.user.id
    );

  if (!walletInfo.wallet) {
    return bad(
      500,
      "Main wallet could not be found."
    );
  }

  const balance =
    walletInfo.balance;

  if (
    balance < amount
  ) {
    return bad(
      400,
      "Insufficient Main Wallet balance."
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
          ${walletInfo.wallet.id},
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
      "Withdrawal request could not be submitted.",
      {
        detail:
          error?.message
      }
    );
  }
}

/* =====================================================
   CUSTOMER INVESTMENTS
===================================================== */

async function customerInvestments(
  request,
  url
) {
  const auth =
    await requireCustomer(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
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
        SELECT *
        FROM investments
        WHERE user_id =
          ${auth.user.id}
        ORDER BY created_at DESC
        LIMIT ${limit}
      `;
  } catch (error) {
    return bad(
      500,
      "Unable to load investments.",
      {
        detail:
          error?.message
      }
    );
  }

  return ok({
    investments: rows,
    portfolio: rows,
    kyc_status:
      String(
        auth.user.kyc_status ||
          "pending"
      ).toLowerCase(),
    kyc_required:
      kycRequired(
        auth.user
      )
  });
}

/* =====================================================
   CHAT FOUNDATION
===================================================== */

async function ensureChatFoundation() {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS chat_conversations (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL
          REFERENCES profiles(id)
          ON DELETE CASCADE,
        created_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW()
      )
    `;

    await sql`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id UUID PRIMARY KEY,
        conversation_id UUID NOT NULL
          REFERENCES chat_conversations(id)
          ON DELETE CASCADE,
        sender_id UUID NOT NULL
          REFERENCES profiles(id)
          ON DELETE CASCADE,
        sender_type TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW()
      )
    `;

    return true;
  } catch (error) {
    console.error(
      "Chat foundation error:",
      error
    );

    return false;
  }
}

async function getOrCreateCustomerConversation(
  userId
) {
  const existing =
    await sql`
      SELECT *
      FROM chat_conversations
      WHERE user_id =
        ${userId}
      ORDER BY
        updated_at DESC NULLS LAST,
        created_at DESC
      LIMIT 1
    `;

  if (existing.length) {
    return existing[0];
  }

  const id =
    crypto.randomUUID();

  const rows =
    await sql`
      INSERT INTO chat_conversations (
        id,
        user_id,
        created_at,
        updated_at
      )
      VALUES (
        ${id},
        ${userId},
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  return rows[0];
}

async function customerChat(
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

  const ready =
    await ensureChatFoundation();

  if (!ready) {
    return bad(
      500,
      "Unable to initialize customer support chat."
    );
  }

  const conversation =
    await getOrCreateCustomerConversation(
      auth.user.id
    );

  if (!body) {
    const messages =
      await sql`
        SELECT *
        FROM chat_messages
        WHERE conversation_id =
          ${conversation.id}
        ORDER BY created_at ASC
      `;

    return ok({
      conversation,
      messages
    });
  }

  const message =
    String(
      body.message ||
        body.content ||
        ""
    ).trim();

  if (!message) {
    return bad(
      400,
      "Message cannot be empty."
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
        ${conversation.id},
        ${auth.user.id},
        'customer',
        ${message},
        NOW()
      )
      RETURNING *
    `;

  await sql`
    UPDATE chat_conversations
    SET
      updated_at = NOW()
    WHERE id =
      ${conversation.id}
  `;

  return ok({
    message:
      "Message sent.",
    conversation,
    data:
      rows[0]
  });
}

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
          ON p.id =
            c.user_id
        ORDER BY
          COALESCE(
            c.updated_at,
            c.created_at
          ) DESC
      `;

    return ok({
      conversations:
        rows
    });
  } catch (error) {
    console.error(
      "Admin conversations error:",
      error
    );

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
        SELECT *
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

  if (!conversationId) {
    return bad(
      400,
      "Conversation ID is required."
    );
  }

  const message =
    String(
      body.message ||
        body.content ||
        ""
    ).trim();

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
      WHERE id =
        ${conversationId}
      LIMIT 1
    `;

  if (!conversation.length) {
    return bad(
      404,
      "Conversation not found."
    );
  }

  try {
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
          ${admin.user.id},
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
      WHERE id =
        ${conversationId}
    `;

    return ok({
      message:
        "Message sent.",
      data:
        rows[0]
    });
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
}

/* =====================================================
   ADMIN CUSTOMER UPDATE
   APPROVAL ALSO VERIFIES EMAIL
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
      SELECT *
      FROM profiles
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (!current.length) {
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

  const approvalRequested =
    (
      status !== null &&
      [
        "active",
        "approved"
      ].includes(
        status.toLowerCase()
      )
    );

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

        /*
         * Temporary verification rule:
         * administrator approval immediately
         * verifies the customer's email.
         */
        email_verified_at =
          CASE
            WHEN
              LOWER(
                COALESCE(
                  ${status},
                  status,
                  ''
                )
              )
              IN (
                'active',
                'approved'
              )
            THEN
              COALESCE(
                email_verified_at,
                NOW()
              )
            ELSE
              email_verified_at
          END,

        kyc_status =
          COALESCE(
            ${kycStatus},
            kyc_status
          ),

        updated_at = NOW()

      WHERE id =
        ${id}

      RETURNING *
    `;

  /*
   * If admin approved KYC while no customer
   * submission existed, synchronize the profile
   * directly and do not require a submission.
   */
  if (
    kycStatus ===
    "approved"
  ) {
    try {
      const existing =
        await sql`
          SELECT id
          FROM kyc_submissions
          WHERE user_id =
            ${id}
          ORDER BY created_at DESC
          LIMIT 1
        `;

      if (!existing.length) {
        await sql`
          INSERT INTO kyc_submissions (
            id,
            user_id,
            status,
            reviewed_by,
            reviewed_at,
            created_at,
            updated_at
          )
          VALUES (
            ${crypto.randomUUID()},
            ${id},
            'approved',
            ${admin.user.id},
            NOW(),
            NOW(),
            NOW()
          )
        `;
      } else {
        await sql`
          UPDATE kyc_submissions
          SET
            status = 'approved',
            reviewed_by =
              ${admin.user.id},
            reviewed_at = NOW(),
            updated_at = NOW()
          WHERE id =
            ${existing[0].id}
        `;
      }
    } catch (error) {
      console.warn(
        "KYC synchronization warning:",
        error?.message
      );
    }
  }

  await ensureUserWallets(id);

  return ok({
    message:
      approvalRequested
        ? "Customer approved successfully. Email verification has also been completed."
        : "Customer updated successfully.",
    customer:
      updated[0],
    account_approved:
      customerIsApproved(
        updated[0]
      ),
    email_verified:
      !!updated[0]
        .email_verified_at ||
      customerIsApproved(
        updated[0]
      ),
    kyc_status:
      String(
        updated[0]
          .kyc_status ||
          "pending"
      ).toLowerCase()
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
            ON p.id =
              k.user_id
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
            ON p.id =
              k.user_id
          ORDER BY
            k.created_at DESC
          LIMIT ${limit}
        `;
    }
  } catch (error) {
    console.warn(
      "KYC submissions query fallback:",
      error?.message
    );
  }

  /*
   * Always include profile KYC state so an admin can
   * approve customers even when they never submitted
   * a KYC record.
   */
  const profileRows =
    await sql`
      SELECT
        p.id,
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
        ON r.id =
          p.role_id
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

  const merged = [
    ...rows
  ];

  const seen =
    new Set(
      merged.map(
        item =>
          String(
            item.user_id ||
              item.id ||
              ""
          )
      )
    );

  for (
    const item of profileRows
  ) {
    const key =
      String(
        item.user_id ||
          item.id ||
          ""
      );

    if (!seen.has(key)) {
      merged.push(item);
    }
  }

  return ok({
    submissions:
      merged.slice(
        0,
        limit
      )
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
    decision !==
      "approved" &&
    decision !==
      "rejected"
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
        WHERE id =
          ${id}
        LIMIT 1
      `;
  } catch {
    submission = [];
  }

  let userId = id;

  if (submission.length) {
    userId =
      submission[0]
        .user_id;

    await sql`
      UPDATE kyc_submissions
      SET
        status =
          ${decision},
        reviewed_by =
          ${admin.user.id},
        reviewed_at = NOW(),
        updated_at = NOW()
      WHERE id =
        ${id}
    `;
  } else {
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
  }

  /*
   * This is the critical synchronization:
   * Admin approval updates profiles.kyc_status,
   * which is what the customer dashboard reads.
   */
  const updated =
    await sql`
      UPDATE profiles
      SET
        kyc_status =
          ${decision},
        updated_at = NOW()
      WHERE id =
        ${userId}
      RETURNING *
    `;

  /*
   * If admin approved KYC without a submission,
   * create a record for audit consistency.
   */
  if (
    decision ===
      "approved" &&
    !submission.length
  ) {
    try {
      await sql`
        INSERT INTO kyc_submissions (
          id,
          user_id,
          status,
          reviewed_by,
          reviewed_at,
          created_at,
          updated_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${userId},
          'approved',
          ${admin.user.id},
          NOW(),
          NOW(),
          NOW()
        )
      `;
    } catch (error) {
      console.warn(
        "KYC audit record warning:",
        error?.message
      );
    }
  }

  return ok({
    message:
      `KYC ${decision} successfully.`,
    kyc_status:
      decision,
    customer:
      updated[0]
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
        ON r.id =
          p.role_id
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
        )
        LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.email,
            ''
          )
        )
        LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.first_name ||
              ' ' ||
              p.last_name,
            ''
          )
        )
        LIKE LOWER(
          ${"%" + search + "%"}
        )
      )
      ORDER BY
        p.created_at DESC
      LIMIT ${limit}
    `;

  const result = [];

  for (
    const customer of customers
  ) {
    const state =
      await loadCustomerWalletState(
        customer.user_id
      );

    result.push({
      id:
        state.main?.id ||
        state.profit?.id ||
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
        state.main?.currency ||
        state.profit?.currency ||
        "USD",

      status:
        state.main?.status ||
        state.profit?.status ||
        "active",

      main_wallet_id:
        state.main?.id ||
        null,

      profit_wallet_id:
        state.profit?.id ||
        null,

      main_balance:
        state.mainBalance,

      profit_balance:
        state.profitBalance,

      total_balance:
        state.totalBalance,

      created_at:
        state.main?.created_at ||
        state.profit?.created_at ||
        null,

      updated_at:
        state.main?.updated_at ||
        state.profit?.updated_at ||
        null
    });
  }

  return ok({
    wallets:
      result
  });
}

async function adminWallet(userId) {
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

  const state =
    await loadCustomerWalletState(
      userId
    );

  let ledger = [];

  try {
    ledger =
      await sql`
        SELECT *
        FROM wallet_ledger
        WHERE user_id =
          ${userId}
        ORDER BY
          created_at DESC
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

    wallets:
      state.rows,

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
      body.user_id ||
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

  const state =
    await loadCustomerWalletState(
      userId
    );

  let wallet =
    walletType ===
    "profit"
      ? state.profit
      : state.main;

  let legacy =
    false;

  if (
    walletType ===
      "main" &&
    state.legacy &&
    state.main &&
    state.main.id ===
      state.legacy.id
  ) {
    const typed =
      state.main.wallet_type;

    if (
      !typed &&
      state.legacy.main_balance !==
        undefined
    ) {
      legacy = true;
      wallet =
        state.legacy;
    }
  }

  if (
    !wallet &&
    state.legacy
  ) {
    wallet =
      state.legacy;

    legacy = true;
  }

  if (!wallet) {
    return bad(
      404,
      "Customer wallet not found."
    );
  }

  const current =
    walletType ===
      "profit"
      ? (
          legacy
            ? numberValue(
                wallet.profit_balance,
                0
              )
            : numberValue(
                wallet.balance,
                0
              )
        )
      : (
          legacy
            ? numberValue(
                wallet.main_balance,
                0
              )
            : numberValue(
                wallet.balance,
                0
              )
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

  if (legacy) {
    if (
      walletType ===
      "profit"
    ) {
      updated =
        await sql`
          UPDATE wallets
          SET
            profit_balance =
              ${next},
            updated_at = NOW()
          WHERE id =
            ${wallet.id}
          RETURNING *
        `;
    } else {
      updated =
        await sql`
          UPDATE wallets
          SET
            main_balance =
              ${next},
            updated_at = NOW()
          WHERE id =
            ${wallet.id}
          RETURNING *
        `;
    }
  } else {
    updated =
      await sql`
        UPDATE wallets
        SET
          balance =
            ${next},
          updated_at = NOW()
        WHERE id =
          ${wallet.id}
        RETURNING *
      `;
  }

  const transactionReference =
    `ADJ-${crypto.randomUUID()}`;

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
      "Wallet ledger insert failed:",
      error
    );

    /*
     * Roll back wallet update if the ledger
     * cannot be recorded.
     */
    if (legacy) {
      if (
        walletType ===
        "profit"
      ) {
        await sql`
          UPDATE wallets
          SET
            profit_balance =
              ${current},
            updated_at = NOW()
          WHERE id =
            ${wallet.id}
        `;
      } else {
        await sql`
          UPDATE wallets
          SET
            main_balance =
              ${current},
            updated_at = NOW()
          WHERE id =
            ${wallet.id}
        `;
      }
    } else {
      await sql`
        UPDATE wallets
        SET
          balance =
            ${current},
          updated_at = NOW()
        WHERE id =
          ${wallet.id}
      `;
    }

    return bad(
      500,
      "Wallet was not updated because the wallet ledger could not be created.",
      {
        detail:
          error?.message
      }
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
    console.error(
      "Admin wallet transaction insert failed:",
      error
    );

    /*
     * Roll back both the wallet and the
     * ledger entry.
     */
    if (legacy) {
      if (
        walletType ===
        "profit"
      ) {
        await sql`
          UPDATE wallets
          SET
            profit_balance =
              ${current},
            updated_at = NOW()
          WHERE id =
            ${wallet.id}
        `;
      } else {
        await sql`
          UPDATE wallets
          SET
            main_balance =
              ${current},
            updated_at = NOW()
          WHERE id =
            ${wallet.id}
        `;
      }
    } else {
      await sql`
        UPDATE wallets
        SET
          balance =
            ${current},
          updated_at = NOW()
        WHERE id =
          ${wallet.id}
      `;
    }

    try {
      await sql`
        DELETE FROM wallet_ledger
        WHERE user_id =
          ${userId}
          AND wallet_type =
            ${walletType}
          AND amount =
            ${amount}
          AND balance_before =
            ${current}
          AND balance_after =
            ${next}
          AND created_by =
            ${admin.user.id}
          AND entry_type =
            'admin_adjustment'
        ORDER BY created_at DESC
        LIMIT 1
      `;
    } catch {}

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
    main_balance:
      walletType ===
      "main"
        ? next
        : state.mainBalance,
    profit_balance:
      walletType ===
      "profit"
        ? next
        : state.profitBalance,
    transaction_reference:
      transactionReference
  });
}

/* =====================================================
   ADMIN TRANSACTIONS
===================================================== */

async function adminTransactions(url) {
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
    console.error(
      "Admin transaction query failed:",
      error
    );

    return bad(
      500,
      "Unable to load transactions.",
      {
        detail:
          error?.message
      }
    );
  }

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
            ON p.id =
              wl.user_id
          ORDER BY
            wl.created_at DESC
          LIMIT ${limit}
        `;

      rows =
        ledgerRows.map(
          item => ({
            id:
              item.id,
            user_id:
              item.user_id,
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
            currency:
              "USD",
            status:
              "completed",
            description:
              item.description ||
              "Wallet activity",
            wallet_type:
              item.wallet_type,
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
    transactions:
      rows
  });
}

/* =====================================================
   ADMIN INVESTMENTS
===================================================== */

async function adminInvestments(url) {
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
          i.*,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM investments i
        LEFT JOIN profiles p
          ON p.id =
            i.user_id
        ORDER BY
          i.created_at DESC
        LIMIT ${limit}
      `;
  } catch (error) {
    return bad(
      500,
      "Unable to load investments.",
      {
        detail:
          error?.message
      }
    );
  }

  return ok({
    investments:
      rows
  });
}

/* =====================================================
   ADMIN REQUESTS
===================================================== */

async function adminRequests(url) {
  const status =
    String(
      url.searchParams.get(
        "status"
      ) ||
        "pending"
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

  try {
    const deposits =
      await sql`
        SELECT
          d.id,
          d.deposit_reference
            AS request_reference,
          d.user_id,
          d.wallet_id,
          d.amount,
          d.currency,
          d.payment_method,
          d.payment_reference,
          d.proof_url,
          d.status,
          d.submitted_at
            AS created_at,
          d.reviewed_at,
          d.reviewed_by,
          d.admin_notes,
          'deposit'
            AS type,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM deposit_requests d
        LEFT JOIN profiles p
          ON p.id =
            d.user_id
        WHERE LOWER(
          COALESCE(
            d.status,
            'pending'
          )
        ) = ${status}
        ORDER BY
          d.submitted_at DESC
        LIMIT ${limit}
      `;

    const withdrawals =
      await sql`
        SELECT
          w.id,
          w.withdrawal_reference
            AS request_reference,
          w.user_id,
          w.wallet_id,
          w.amount,
          w.currency,
          w.withdrawal_method
            AS payment_method,
          NULL
            AS payment_reference,
          NULL
            AS proof_url,
          w.status,
          w.requested_at
            AS created_at,
          w.reviewed_at,
          w.reviewed_by,
          w.admin_notes,
          'withdrawal'
            AS type,
          p.first_name,
          p.last_name,
          p.username,
          p.email
        FROM withdrawal_requests w
        LEFT JOIN profiles p
          ON p.id =
            w.user_id
        WHERE LOWER(
          COALESCE(
            w.status,
            'pending'
          )
        ) = ${status}
        ORDER BY
          w.requested_at DESC
        LIMIT ${limit}
      `;

    const rows = [
      ...deposits,
      ...withdrawals
    ].sort(
      (a, b) =>
        new Date(
          b.created_at
        ).getTime() -
        new Date(
          a.created_at
        ).getTime()
    );

    return ok({
      requests:
        rows.slice(
          0,
          limit
        )
    });
  } catch (error) {
    return bad(
      500,
      "Unable to load pending requests.",
      {
        detail:
          error?.message
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
    decision !==
      "approved" &&
    decision !==
      "rejected"
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

  let requestType = null;
  let item = null;

  const depositRows =
    await sql`
      SELECT *
      FROM deposit_requests
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (depositRows.length) {
    requestType =
      "deposit";
    item =
      depositRows[0];
  } else {
    const withdrawalRows =
      await sql`
        SELECT *
        FROM withdrawal_requests
        WHERE id =
          ${id}
        LIMIT 1
      `;

    if (
      withdrawalRows.length
    ) {
      requestType =
        "withdrawal";
      item =
        withdrawalRows[0];
    }
  }

  if (!item) {
    return bad(
      404,
      "Request not found."
    );
  }

  const currentStatus =
    String(
      item.status ||
        "pending"
    )
      .trim()
      .toLowerCase();

  if (
    currentStatus !==
    "pending"
  ) {
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

  if (
    decision ===
    "rejected"
  ) {
    if (
      requestType ===
      "deposit"
    ) {
      const updated =
        await sql`
          UPDATE deposit_requests
          SET
            status =
              'rejected',
            reviewed_by =
              ${admin.user.id},
            reviewed_at =
              NOW(),
            admin_notes =
              COALESCE(
                ${
                  body.admin_notes ||
                  body.notes ||
                  null
                },
                admin_notes
              ),
            updated_at =
              NOW()
          WHERE id =
            ${id}
            AND LOWER(
              COALESCE(
                status,
                'pending'
              )
            ) = 'pending'
          RETURNING *
        `;

      return ok({
        message:
          "Deposit request rejected successfully.",
        request: {
          ...updated[0],
          type:
            "deposit"
        }
      });
    }

    const updated =
      await sql`
        UPDATE withdrawal_requests
        SET
          status =
            'rejected',
          reviewed_by =
            ${admin.user.id},
          reviewed_at =
            NOW(),
          admin_notes =
            COALESCE(
              ${
                body.admin_notes ||
                body.notes ||
                null
              },
              admin_notes
            ),
          updated_at =
            NOW()
        WHERE id =
          ${id}
          AND LOWER(
            COALESCE(
              status,
              'pending'
            )
          ) = 'pending'
        RETURNING *
      `;

    return ok({
      message:
        "Withdrawal request rejected successfully.",
      request: {
        ...updated[0],
        type:
          "withdrawal"
      }
    });
  }

  if (
    requestType ===
    "deposit"
  ) {
    await ensureUserWallets(
      item.user_id
    );

    const walletInfo =
      await getCustomerMainWallet(
        item.user_id
      );

    if (!walletInfo.wallet) {
      return bad(
        500,
        "Main wallet could not be found for this customer."
      );
    }

    const wallet =
      walletInfo.wallet;

    const oldBalance =
      walletInfo.balance;

    const newBalance =
      oldBalance +
      amount;

    await setCustomerMainWalletBalance(
      wallet,
      newBalance,
      walletInfo.legacy
    );

    const transactionReference =
      `DEP-${String(
        item.deposit_reference ||
          id
      )}-${crypto.randomUUID()}`;

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
          ${
            item.currency ||
            "USD"
          },
          'completed',
          'Deposit approved by administrator',
          ${JSON.stringify({
            source:
              "deposit_request_approval",
            request_id:
              item.id,
            deposit_reference:
              item.deposit_reference ||
              null
          })},
          NOW(),
          NOW()
        )
      `;

      const updated =
        await sql`
          UPDATE deposit_requests
          SET
            status =
              'approved',
            reviewed_by =
              ${admin.user.id},
            reviewed_at =
              NOW(),
            updated_at =
              NOW()
          WHERE id =
            ${id}
            AND LOWER(
              COALESCE(
                status,
                'pending'
              )
            ) = 'pending'
          RETURNING *
        `;

      if (!updated.length) {
        throw new Error(
          "Deposit request is no longer pending."
        );
      }

      return ok({
        message:
          "Deposit request approved successfully.",
        request: {
          ...updated[0],
          type:
            "deposit"
        }
      });
    } catch (error) {
      await setCustomerMainWalletBalance(
        wallet,
        oldBalance,
        walletInfo.legacy
      );

      return bad(
        500,
        "Deposit could not be approved.",
        {
          detail:
            error?.message
        }
      );
    }
  }

  if (
    requestType ===
    "withdrawal"
  ) {
    await ensureUserWallets(
      item.user_id
    );

    const walletInfo =
      await getCustomerMainWallet(
        item.user_id
      );

    if (!walletInfo.wallet) {
      return bad(
        500,
        "Withdrawal wallet could not be found."
      );
    }

    const wallet =
      walletInfo.wallet;

    const oldBalance =
      walletInfo.balance;

    if (
      oldBalance < amount
    ) {
      return bad(
        400,
        "Insufficient Main Wallet balance for this withdrawal."
      );
    }

    const newBalance =
      oldBalance -
      amount;

    await setCustomerMainWalletBalance(
      wallet,
      newBalance,
      walletInfo.legacy
    );

    const transactionId =
      crypto.randomUUID();

    const transactionReference =
      `WTH-${String(
        item.withdrawal_reference ||
          id
      )}-${crypto.randomUUID()}`;

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
          ${numberValue(
            item.fee,
            0
          )},
          ${
            item.currency ||
            "USD"
          },
          'completed',
          'Withdrawal approved by administrator',
          ${JSON.stringify({
            source:
              "withdrawal_request_approval",
            request_id:
              item.id,
            withdrawal_reference:
              item.withdrawal_reference ||
              null,
            withdrawal_method:
              item.withdrawal_method ||
              null
          })},
          NOW(),
          NOW()
        )
      `;

      const updated =
        await sql`
          UPDATE withdrawal_requests
          SET
            status =
              'approved',
            reviewed_by =
              ${admin.user.id},
            reviewed_at =
              NOW(),
            processed_at =
              NOW(),
            transaction_id =
              ${transactionId},
            updated_at =
              NOW()
          WHERE id =
            ${id}
            AND LOWER(
              COALESCE(
                status,
                'pending'
              )
            ) = 'pending'
          RETURNING *
        `;

      if (!updated.length) {
        throw new Error(
          "Withdrawal request is no longer pending."
        );
      }

      return ok({
        message:
          "Withdrawal request approved successfully.",
        request: {
          ...updated[0],
          type:
            "withdrawal"
        }
      });
    } catch (error) {
      await setCustomerMainWalletBalance(
        wallet,
        oldBalance,
        walletInfo.legacy
      );

      return bad(
        500,
        "Withdrawal could not be approved.",
        {
          detail:
            error?.message
        }
      );
    }
  }

  return bad(
    400,
    "Unsupported request type."
  );
}

/* =====================================================
   ADMIN ACTIVITY
===================================================== */

async function adminActivity() {
  const activities = [];

  try {
    const rows =
      await sql`
        SELECT
          t.id,
          'transaction'
            AS activity_type,
          COALESCE(
            t.transaction_type,
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
          ON p.id =
            t.user_id
        ORDER BY
          t.created_at DESC
        LIMIT 50
      `;

    activities.push(
      ...rows
    );
  } catch {}

  try {
    const rows =
      await sql`
        SELECT
          i.id,
          'investment'
            AS activity_type,
          'investment_created'
            AS action,
          COALESCE(
            i.principal_amount,
            i.amount,
            0
          ) AS amount,
          NULL AS direction,
          i.status,
          'USD'
            AS currency,
          NULL
            AS description,
          i.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          i.created_at
        FROM investments i
        LEFT JOIN profiles p
          ON p.id =
            i.user_id
        ORDER BY
          i.created_at DESC
        LIMIT 50
      `;

    activities.push(
      ...rows
    );
  } catch {}

  try {
    const rows =
      await sql`
        SELECT
          wl.id,
          'wallet'
            AS activity_type,
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
          'completed'
            AS status,
          'USD'
            AS currency,
          wl.description,
          wl.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          wl.created_at
        FROM wallet_ledger wl
        LEFT JOIN profiles p
          ON p.id =
            wl.user_id
        ORDER BY
          wl.created_at DESC
        LIMIT 50
      `;

    activities.push(
      ...rows
    );
  } catch {}

  try {
    const deposits =
      await sql`
        SELECT
          d.id,
          'request'
            AS activity_type,
          'deposit'
            AS action,
          d.amount,
          NULL AS direction,
          d.status,
          d.currency,
          NULL
            AS description,
          d.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          d.submitted_at
            AS created_at
        FROM deposit_requests d
        LEFT JOIN profiles p
          ON p.id =
            d.user_id
        ORDER BY
          d.submitted_at DESC
        LIMIT 50
      `;

    activities.push(
      ...deposits
    );
  } catch {}

  try {
    const withdrawals =
      await sql`
        SELECT
          w.id,
          'request'
            AS activity_type,
          'withdrawal'
            AS action,
          w.amount,
          NULL AS direction,
          w.status,
          w.currency,
          NULL
            AS description,
          w.user_id,
          p.first_name,
          p.last_name,
          p.username,
          p.email,
          w.requested_at
            AS created_at
        FROM withdrawal_requests w
        LEFT JOIN profiles p
          ON p.id =
            w.user_id
        ORDER BY
          w.requested_at DESC
        LIMIT 50
      `;

    activities.push(
      ...withdrawals
    );
  } catch {}

  try {
    const ready =
      await ensureChatFoundation();

    if (ready) {
      const rows =
        await sql`
          SELECT
            m.id,
            'chat'
              AS activity_type,
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
            'completed'
              AS status,
            NULL AS currency,
            m.message
              AS description,
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
          ORDER BY
            m.created_at DESC
          LIMIT 30
        `;

      activities.push(
        ...rows
      );
    }
  } catch {}

  activities.sort(
    (a, b) =>
      new Date(
        b.created_at || 0
      ).getTime() -
      new Date(
        a.created_at || 0
      ).getTime()
  );

  return ok({
    activity:
      activities.slice(
        0,
        50
      ),
    activities:
      activities.slice(
        0,
        50
      )
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
    transactions
  ] =
    await Promise.all([
      sql`
        SELECT COUNT(*)::int
          AS count
        FROM profiles p
        LEFT JOIN roles r
          ON r.id =
            p.role_id
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
      `,

      sql`
        SELECT COUNT(*)::int
          AS count
        FROM profiles
        WHERE LOWER(
          COALESCE(
            kyc_status,
            'pending'
          )
        ) = 'pending'
      `,

      sql`
        SELECT COUNT(*)::int
          AS count
        FROM investments
      `,

      sql`
        SELECT COUNT(*)::int
          AS count
        FROM transactions
      `
    ]);

  let pendingRequests = 0;

  try {
    const deposits =
      await sql`
        SELECT COUNT(*)::int
          AS count
        FROM deposit_requests
        WHERE LOWER(
          COALESCE(
            status,
            'pending'
          )
        ) = 'pending'
      `;

    const withdrawals =
      await sql`
        SELECT COUNT(*)::int
          AS count
        FROM withdrawal_requests
        WHERE LOWER(
          COALESCE(
            status,
            'pending'
          )
        ) = 'pending'
      `;

    pendingRequests =
      (
        deposits[0]?.count ||
        0
      ) +
      (
        withdrawals[0]?.count ||
        0
      );
  } catch {}

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
        pendingRequests
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
        ON r.id =
          p.role_id
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
        )
        LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.last_name,
            ''
          )
        )
        LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.username,
            ''
          )
        )
        LIKE LOWER(
          ${"%" + search + "%"}
        )
        OR LOWER(
          COALESCE(
            p.email,
            ''
          )
        )
        LIKE LOWER(
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
        ON r.id =
          p.role_id
      WHERE p.id =
        ${id}
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
          ON r.id =
            p.role_id
        WHERE LOWER(
          p.email
        ) = ${email}
        AND LOWER(
          r.name
        ) = 'admin'
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
    const [key, value] of
      Object.entries(
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
      req.body !==
        undefined &&
      req.body !==
        null
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
  if (res.headersSent) {
    return;
  }

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

    /* HEALTH */

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

    /* REGISTER */

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

    /* LOGIN */

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

    /* VERIFY EMAIL */

    if (
      method === "POST" &&
      path ===
        "/api/auth/verify-email"
    ) {
      const body =
        await jsonBody(
          request
        );

      return writeWebResponse(
        res,
        await verifyEmail(
          body.token
        )
      );
    }

    /* LOGOUT */

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

    /* CURRENT USER */

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

    /* ADMIN RESET */

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

    /* CUSTOMER DASHBOARD */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/dashboard" ||
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

    /* CUSTOMER WALLETS */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/wallets" ||
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

    /* CUSTOMER TRANSACTIONS */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/transactions" ||
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

    /* CUSTOMER PROFILE */

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

    /* CUSTOMER KYC */

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

    /* CUSTOMER DEPOSIT */

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

    /* CUSTOMER SEND */

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

    /* WITHDRAWAL ACCOUNT */

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

    /* CUSTOMER WITHDRAW */

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

    /* CUSTOMER INVESTMENTS */

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

    /* CUSTOMER CHAT */

    if (
      method === "GET" &&
      (
        path ===
          "/api/customer/chat" ||
        path ===
          "/api/user/chat" ||
        path ===
          "/api/chat"
      )
    ) {
      return writeWebResponse(
        res,
        await customerChat(
          request
        )
      );
    }

    if (
      method === "POST" &&
      (
        path ===
          "/api/customer/chat" ||
        path ===
          "/api/user/chat" ||
        path ===
          "/api/chat"
      )
    ) {
      return writeWebResponse(
        res,
        await customerChat(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* ADMIN DASHBOARD */

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

    /* ADMIN ACTIVITY */

    if (
      method === "GET" &&
      path ===
        "/api/admin/activity"
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
        await adminActivity()
      );
    }

    /* ADMIN CUSTOMERS */

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
        method === "PATCH" ||
        method === "POST"
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
          await jsonBody(
            request
          )
        )
      );
    }

    /* ADMIN WALLETS */

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

    /* ADMIN KYC */

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
        path.split("/").pop();

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

    /* ADMIN INVESTMENTS */

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

      return writeWebResponse(
        res,
        await adminInvestments(
          url
        )
      );
    }

    /* ADMIN TRANSACTIONS */

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

      return writeWebResponse(
        res,
        await adminTransactions(
          url
        )
      );
    }

    /* ADMIN REQUESTS */

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
        await adminRequests(
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
          await jsonBody(
            request
          )
        )
      );
    }

    /* ADMIN CHAT */

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

      const conversationId =
        url.searchParams.get(
          "conversation_id"
        );

      if (
        conversationId
      ) {
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
      const conversationId =
        path.split("/").pop();

      return writeWebResponse(
        res,
        await adminSendMessage(
          request,
          conversationId,
          await jsonBody(
            request
          )
        )
      );
    }

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
