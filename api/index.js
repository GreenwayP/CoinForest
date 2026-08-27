/* COMPLETE UPDATED INDEX.JS
   CoinForest — Customer Dashboard / Admin API
   FIXED:
   - Restored customer login/register/logout routes
   - /api/auth/login restored
   - Session creation restored
   - Admin account approval => temporary email verification
   - Unapproved customers can log in but cannot perform protected actions
   - Customer KYC application + admin KYC approval sync
   - Customer/admin wallet synchronization
   - Customer transaction history
   - Deposit / send / withdrawal handling
   - Withdrawal account storage
   - Customer/admin chat
   - Admin activity
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

/* =========================================================
   DATABASE HELPERS
   ========================================================= */

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

    return Boolean(rows[0]?.exists);
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

    return Boolean(rows[0]?.exists);
  } catch {
    return false;
  }
}

async function firstExistingTable(names) {
  for (const name of names) {
    if (await tableExists(name)) {
      return name;
    }
  }

  return null;
}

async function getUserById(userId) {
  if (!userId) return null;

  try {
    const rows = await sql`
      SELECT *
      FROM users
      WHERE id = ${userId}
      LIMIT 1
    `;

    return rows[0] || null;
  } catch {
    return null;
  }
}

async function getUserByEmail(email) {
  const normalized = normalizeEmail(email);

  if (!normalized) return null;

  try {
    const rows = await sql`
      SELECT *
      FROM users
      WHERE LOWER(email) = ${normalized}
      LIMIT 1
    `;

    return rows[0] || null;
  } catch {
    return null;
  }
}

/* =========================================================
   ACCOUNT APPROVAL / EMAIL VERIFICATION
   ========================================================= */

function accountApproved(user) {
  if (!user) return false;

  return Boolean(
    user.account_approved === true ||
    user.accountApproved === true ||
    user.approved === true ||
    user.is_approved === true ||
    user.status === "approved" ||
    user.status === "active" ||
    user.account_status === "approved" ||
    user.account_status === "active"
  );
}

function emailVerified(user) {
  if (!user) return false;

  /*
    Temporary CoinForest rule:

    Admin account approval is the source of truth for
    email verification until Resend / official-domain
    verification is available.

    An approved account therefore behaves as email verified.
  */

  if (accountApproved(user)) {
    return true;
  }

  return Boolean(
    user.email_verified === true ||
    user.emailVerified === true ||
    user.is_email_verified === true ||
    user.verified === true
  );
}

function customerCanAct(user) {
  if (!user) return false;

  /*
    Unapproved customers may log in, but they may not
    perform customer actions.

    Once admin approves the account, approval also means
    email verification under the temporary system.
  */

  return accountApproved(user) && emailVerified(user);
}

/* =========================================================
   KYC HELPERS
   ========================================================= */

function normalizeKycStatus(user) {
  if (!user) return "pending";

  const raw =
    user.kyc_status ??
    user.kycStatus ??
    user.kyc_state ??
    user.kycState ??
    "";

  const status = String(raw).trim().toLowerCase();

  if (
    user.kyc_verified === true ||
    user.kycVerified === true ||
    user.kyc_approved === true ||
    user.kycApproved === true ||
    status === "approved" ||
    status === "verified" ||
    status === "complete" ||
    status === "completed"
  ) {
    return "approved";
  }

  if (
    status === "rejected" ||
    status === "declined"
  ) {
    return "rejected";
  }

  if (
    status === "submitted" ||
    status === "under_review" ||
    status === "review"
  ) {
    return "submitted";
  }

  return "pending";
}

function kycApproved(user) {
  return normalizeKycStatus(user) === "approved";
}

/* =========================================================
   WALLET HELPERS
   ========================================================= */

const MAIN_WALLET_NAMES = [
  "main",
  "main_wallet",
  "Main Wallet",
  "MAIN",
  "usd",
  "USD"
];

const PROFIT_WALLET_NAMES = [
  "profit",
  "profit_wallet",
  "Profit Wallet",
  "PROFIT"
];

function walletAmount(row) {
  if (!row) return 0;

  return numberValue(
    row.balance ??
    row.amount ??
    row.available_balance ??
    row.available ??
    row.current_balance ??
    0
  );
}

function walletCurrency(row) {
  return String(
    row?.currency ??
    row?.asset ??
    row?.symbol ??
    "USD"
  ).toUpperCase();
}

function walletType(row) {
  return String(
    row?.wallet_type ??
    row?.walletType ??
    row?.type ??
    row?.name ??
    "main"
  ).trim().toLowerCase();
}

function isMainWallet(row) {
  if (!row) return false;

  const type = walletType(row);

  return (
    MAIN_WALLET_NAMES
      .map(v => v.toLowerCase())
      .includes(type) ||
    type.includes("main") ||
    type.includes("cash")
  );
}

function isProfitWallet(row) {
  if (!row) return false;

  const type = walletType(row);

  return (
    PROFIT_WALLET_NAMES
      .map(v => v.toLowerCase())
      .includes(type) ||
    type.includes("profit")
  );
}

async function getWalletRows(userId) {
  if (!userId) return [];

  const candidates = [
    "wallets",
    "user_wallets",
    "wallet"
  ];

  const table = await firstExistingTable(candidates);

  if (!table) return [];

  try {
    if (table === "wallets") {
      return await sql`
        SELECT *
        FROM wallets
        WHERE user_id = ${userId}
        ORDER BY created_at ASC NULLS FIRST
      `;
    }

    if (table === "user_wallets") {
      return await sql`
        SELECT *
        FROM user_wallets
        WHERE user_id = ${userId}
        ORDER BY created_at ASC NULLS FIRST
      `;
    }

    return await sql`
      SELECT *
      FROM wallet
      WHERE user_id = ${userId}
      ORDER BY created_at ASC NULLS FIRST
    `;
  } catch {
    return [];
  }
}

function summarizeWallets(rows) {
  let main = 0;
  let profit = 0;

  for (const row of rows) {
    const amount = walletAmount(row);

    if (isProfitWallet(row)) {
      profit += amount;
      continue;
    }

    if (isMainWallet(row)) {
      main += amount;
      continue;
    }

    /*
      Legacy / unnamed wallet records are treated as Main Wallet.
      This prevents an old funded wallet from appearing as zero
      merely because a newer typed wallet exists.
    */
    main += amount;
  }

  return {
    main,
    profit,
    total: main + profit
  };
}

async function getCustomerWallet(userId) {
  const rows = await getWalletRows(userId);
  const summary = summarizeWallets(rows);

  return {
    rows,
    main: summary.main,
    profit: summary.profit,
    total: summary.total
  };
}

async function updateWalletRow(row, amount) {
  if (!row?.id) return false;

  const table =
    row.__table ||
    "wallets";

  const hasBalance =
    await columnExists(table, "balance");

  const hasAmount =
    await columnExists(table, "amount");

  try {
    if (hasBalance) {
      await sql`
        UPDATE ${sql(table)}
        SET balance = ${amount}
        WHERE id = ${row.id}
      `;
      return true;
    }

    if (hasAmount) {
      await sql`
        UPDATE ${sql(table)}
        SET amount = ${amount}
        WHERE id = ${row.id}
      `;
      return true;
    }
  } catch {
    return false;
  }

  return false;
}

async function ensureWallet(userId, type = "main") {
  const table = await firstExistingTable([
    "wallets",
    "user_wallets",
    "wallet"
  ]);

  if (!table) return null;

  const existingRows = await getWalletRows(userId);

  let existing = null;

  if (type === "profit") {
    existing =
      existingRows.find(isProfitWallet) || null;
  } else {
    existing =
      existingRows.find(isMainWallet) ||
      existingRows.find(
        row => !isProfitWallet(row)
      ) ||
      null;
  }

  if (existing) return existing;

  try {
    const balanceColumn =
      await columnExists(table, "balance");

    const amountColumn =
      await columnExists(table, "amount");

    const typeColumn =
      await columnExists(table, "wallet_type");

    const nameColumn =
      await columnExists(table, "name");

    if (typeColumn && balanceColumn) {
      const rows = await sql`
        INSERT INTO ${sql(table)}
          (user_id, wallet_type, balance)
        VALUES
          (
            ${userId},
            ${type},
            0
          )
        RETURNING *
      `;

      return rows[0] || null;
    }

    if (typeColumn && amountColumn) {
      const rows = await sql`
        INSERT INTO ${sql(table)}
          (user_id, wallet_type, amount)
        VALUES
          (
            ${userId},
            ${type},
            0
          )
        RETURNING *
      `;

      return rows[0] || null;
    }

    if (nameColumn && balanceColumn) {
      const rows = await sql`
        INSERT INTO ${sql(table)}
          (user_id, name, balance)
        VALUES
          (
            ${userId},
            ${
              type === "profit"
                ? "Profit Wallet"
                : "Main Wallet"
            },
            0
          )
        RETURNING *
      `;

      return rows[0] || null;
    }

    if (balanceColumn) {
      const rows = await sql`
        INSERT INTO ${sql(table)}
          (user_id, balance)
        VALUES
          (
            ${userId},
            0
          )
        RETURNING *
      `;

      return rows[0] || null;
    }

    if (amountColumn) {
      const rows = await sql`
        INSERT INTO ${sql(table)}
          (user_id, amount)
        VALUES
          (
            ${userId},
            0
          )
        RETURNING *
      `;

      return rows[0] || null;
    }
  } catch {
    return null;
  }

  return null;
}

/* =========================================================
   WALLET COMPATIBILITY / SYNCHRONIZATION
   ========================================================= */

async function synchronizeWalletRepresentations(
  userId,
  preferredMainBalance = null,
  preferredProfitBalance = null
) {
  const walletData = await getCustomerWallet(userId);

  let mainBalance =
    preferredMainBalance === null
      ? walletData.main
      : numberValue(preferredMainBalance);

  let profitBalance =
    preferredProfitBalance === null
      ? walletData.profit
      : numberValue(preferredProfitBalance);

  /*
    If a typed Main Wallet is zero but a legacy wallet contains
    funds, preserve the funded legacy balance.
  */
  if (
    preferredMainBalance === null &&
    mainBalance === 0 &&
    walletData.rows.length > 0
  ) {
    const legacyRows =
      walletData.rows.filter(
        row =>
          !isProfitWallet(row) &&
          !isMainWallet(row)
      );

    const legacyBalance = legacyRows.reduce(
      (sum, row) => sum + walletAmount(row),
      0
    );

    if (legacyBalance > 0) {
      mainBalance = legacyBalance;
    }
  }

  return {
    main: mainBalance,
    profit: profitBalance,
    total: mainBalance + profitBalance
  };
}

/* =========================================================
   TRANSACTION HELPERS
   ========================================================= */

async function transactionTable() {
  return firstExistingTable([
    "transactions",
    "transaction_history",
    "wallet_transactions",
    "transactions_history"
  ]);
}

function transactionAmount(row) {
  return numberValue(
    row?.amount ??
    row?.value ??
    row?.quantity ??
    0
  );
}

function transactionType(row) {
  return String(
    row?.type ??
    row?.transaction_type ??
    row?.action ??
    ""
  ).toLowerCase();
}

function normalizeTransaction(row) {
  return {
    id: row?.id ?? null,
    user_id: row?.user_id ?? null,
    type:
      row?.type ??
      row?.transaction_type ??
      row?.action ??
      "transaction",
    amount: transactionAmount(row),
    currency:
      row?.currency ??
      row?.asset ??
      "USD",
    status:
      row?.status ??
      "completed",
    description:
      row?.description ??
      row?.note ??
      row?.details ??
      "",
    created_at:
      row?.created_at ??
      row?.timestamp ??
      new Date().toISOString(),
    updated_at:
      row?.updated_at ??
      null
  };
}

/* =========================================================
   AUTHENTICATION
   ========================================================= */

async function createSession(userId) {
  const rawToken = createToken();
  const tokenHash = hashToken(rawToken);

  const sessionsExist =
    await tableExists("sessions");

  if (!sessionsExist) {
    /*
      Compatibility with installations that do not yet have
      a sessions table. If session_token exists, persist there.
    */
    try {
      if (
        await columnExists(
          "users",
          "session_token"
        )
      ) {
        await sql`
          UPDATE users
          SET session_token = ${rawToken}
          WHERE id = ${userId}
        `;
      }
    } catch {}

    return rawToken;
  }

  try {
    await sql`
      INSERT INTO sessions
        (user_id, token, created_at)
      VALUES
        (
          ${userId},
          ${tokenHash},
          NOW()
        )
    `;

    return rawToken;
  } catch {
    /*
      Compatibility fallback for legacy users table sessions.
    */
    try {
      if (
        await columnExists(
          "users",
          "session_token"
        )
      ) {
        await sql`
          UPDATE users
          SET session_token = ${rawToken}
          WHERE id = ${userId}
        `;
      }
    } catch {}

    return rawToken;
  }
}

async function getUserFromToken(token) {
  if (!token) return null;

  const tokenHash = hashToken(token);

  try {
    const sessionExists =
      await tableExists("sessions");

    if (sessionExists) {
      const rows = await sql`
        SELECT u.*
        FROM sessions s
        JOIN users u
          ON u.id = s.user_id
        WHERE s.token = ${tokenHash}
        ORDER BY s.created_at DESC
        LIMIT 1
      `;

      if (rows[0]) {
        return rows[0];
      }

      /*
        Compatibility with installations where the sessions
        table accidentally contains raw tokens.
      */
      try {
        const rawRows = await sql`
          SELECT u.*
          FROM sessions s
          JOIN users u
            ON u.id = s.user_id
          WHERE s.token = ${token}
          ORDER BY s.created_at DESC
          LIMIT 1
        `;

        if (rawRows[0]) {
          return rawRows[0];
        }
      } catch {}
    }
  } catch {
    /* continue */
  }

  /*
    Compatibility:
    Some older deployments stored the raw token directly
    on users.session_token.
  */
  try {
    const rows = await sql`
      SELECT *
      FROM users
      WHERE session_token = ${token}
      LIMIT 1
    `;

    return rows[0] || null;
  } catch {
    return null;
  }
}

async function requireUser(request) {
  const token = bearer(request);

  if (!token) {
    return {
      user: null,
      error: bad(
        401,
        "Authentication required"
      )
    };
  }

  const user = await getUserFromToken(token);

  if (!user) {
    return {
      user: null,
      error: bad(
        401,
        "Invalid or expired session"
      )
    };
  }

  return {
    user,
    error: null
  };
}

async function requireApprovedUser(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth;
  }

  if (!accountApproved(auth.user)) {
    return {
      user: auth.user,
      error: bad(
        403,
        "Account approval is required before performing this action",
        {
          code: "ACCOUNT_NOT_APPROVED",
          account_approved: false,
          email_verified: false
        }
      )
    };
  }

  return auth;
}

/* =========================================================
   LOGIN
   ========================================================= */

async function login(body) {
  const email = normalizeEmail(
    body.email ??
    body.identifier ??
    body.username ??
    ""
  );

  const password = String(
    body.password ??
    body.pass ??
    ""
  );

  if (!email || !password) {
    return bad(
      400,
      "Email and password are required"
    );
  }

  const user =
    await getUserByEmail(email);

  if (!user) {
    return bad(
      401,
      "Invalid email or password",
      {
        code:
          "INVALID_CREDENTIALS"
      }
    );
  }

  const storedPassword =
    String(
      user.password_hash ??
      user.passwordHash ??
      user.password ??
      user.pass_hash ??
      user.passHash ??
      ""
    );

  if (!storedPassword) {
    return bad(
      500,
      "Password authentication is not configured for this account",
      {
        code:
          "PASSWORD_NOT_CONFIGURED"
      }
    );
  }

  let valid = false;

  if (storedPassword.includes(":")) {
    valid = verifyPassword(
      password,
      storedPassword
    );
  } else {
    /*
      Legacy compatibility.
      Existing accounts that use plaintext password
      storage can still authenticate.
    */
    valid =
      password === storedPassword;
  }

  if (!valid) {
    return bad(
      401,
      "Invalid email or password",
      {
        code:
          "INVALID_CREDENTIALS"
      }
    );
  }

  const token =
    await createSession(user.id);

  const fresh =
    await refreshUserFromDatabase(
      user
    );

  const kyc =
    await resolveKycFromAllSources(
      fresh
    );

  const approved =
    accountApproved(fresh);

  const verified =
    emailVerified(fresh);

  /*
    IMPORTANT:
    Login itself is NEVER blocked by account approval.

    An unapproved customer can sign in and view the account,
    but protected customer actions are blocked until admin
    approves the account.

    Admin approval is also temporary email verification.
  */

  return ok({
    token,
    access_token: token,
    session_token: token,

    /*
      Compatibility session objects for dashboards that
      expect Supabase-like or nested token structures.
    */
    session: {
      access_token: token,
      token
    },

    user: {
      ...publicUser(fresh),

      kyc_status:
        kyc.status,

      kycStatus:
        kyc.status,

      kyc_approved:
        kyc.status === "approved",

      kycApproved:
        kyc.status === "approved"
    },

    account_approved:
      approved,

    accountApproved:
      approved,

    email_verified:
      verified,

    emailVerified:
      verified,

    can_act:
      customerCanAct(fresh),

    authenticated: true
  });
}

/* =========================================================
   REGISTER
   ========================================================= */

async function register(body) {
  const email = normalizeEmail(
    body.email ?? ""
  );

  const password = String(
    body.password ?? ""
  );

  if (!email || !password) {
    return bad(
      400,
      "Email and password are required"
    );
  }

  if (password.length < 6) {
    return bad(
      400,
      "Password must be at least 6 characters"
    );
  }

  const existing =
    await getUserByEmail(email);

  if (existing) {
    return bad(
      409,
      "An account with this email already exists",
      {
        code:
          "EMAIL_EXISTS"
      }
    );
  }

  try {
    const passwordHash =
      hashPassword(password);

    const fullName =
      String(
        body.full_name ??
        body.fullName ??
        body.name ??
        ""
      ).trim();

    const phone =
      String(
        body.phone ??
        body.phone_number ??
        ""
      ).trim();

    const country =
      String(
        body.country ??
        ""
      ).trim();

    const hasPasswordHash =
      await columnExists(
        "users",
        "password_hash"
      );

    const hasPassword =
      await columnExists(
        "users",
        "password"
      );

    const hasFullName =
      await columnExists(
        "users",
        "full_name"
      );

    const hasPhone =
      await columnExists(
        "users",
        "phone"
      );

    const hasCountry =
      await columnExists(
        "users",
        "country"
      );

    const hasAccountApproved =
      await columnExists(
        "users",
        "account_approved"
      );

    const hasStatus =
      await columnExists(
        "users",
        "status"
      );

    const hasEmailVerified =
      await columnExists(
        "users",
        "email_verified"
      );

    const hasKycStatus =
      await columnExists(
        "users",
        "kyc_status"
      );

    const hasCreatedAt =
      await columnExists(
        "users",
        "created_at"
      );

    const hasUpdatedAt =
      await columnExists(
        "users",
        "updated_at"
      );

    if (!hasPasswordHash && !hasPassword) {
      return bad(
        500,
        "Password column is not configured"
      );
    }

    /*
      Build the INSERT using the actual supported users schema.
      The most common installation has password_hash.
    */

    if (
      hasPasswordHash &&
      hasFullName &&
      hasPhone &&
      hasCountry &&
      hasAccountApproved &&
      hasStatus &&
      hasEmailVerified &&
      hasKycStatus
    ) {
      const rows = await sql`
        INSERT INTO users
          (
            email,
            password_hash,
            full_name,
            phone,
            country,
            account_approved,
            status,
            email_verified,
            kyc_status
            ${
              hasCreatedAt
                ? sql`, created_at`
                : sql``
            }
            ${
              hasUpdatedAt
                ? sql`, updated_at`
                : sql``
            }
          )
        VALUES
          (
            ${email},
            ${passwordHash},
            ${fullName},
            ${phone},
            ${country},
            FALSE,
            'pending',
            FALSE,
            'pending'
            ${
              hasCreatedAt
                ? sql`, NOW()`
                : sql``
            }
            ${
              hasUpdatedAt
                ? sql`, NOW()`
                : sql``
            }
          )
        RETURNING *
      `;

      return ok({
        user:
          publicUser(rows[0]),
        account_approved:
          false,
        email_verified:
          false,
        can_act:
          false,
        authenticated:
          false,
        message:
          "Account created. Admin approval is required before customer actions are available."
      });
    }

    /*
      Minimal compatibility fallback.
    */
    if (hasPasswordHash) {
      const rows = await sql`
        INSERT INTO users
          (
            email,
            password_hash
          )
        VALUES
          (
            ${email},
            ${passwordHash}
          )
        RETURNING *
      `;

      return ok({
        user:
          publicUser(rows[0]),
        account_approved:
          false,
        email_verified:
          false,
        can_act:
          false,
        authenticated:
          false,
        message:
          "Account created. Admin approval is required before customer actions are available."
      });
    }

    const rows = await sql`
      INSERT INTO users
        (
          email,
          password
        )
      VALUES
        (
          ${email},
          ${passwordHash}
        )
      RETURNING *
    `;

    return ok({
      user:
        publicUser(rows[0]),
      account_approved:
        false,
      email_verified:
        false,
      can_act:
        false,
      authenticated:
        false,
      message:
        "Account created. Admin approval is required before customer actions are available."
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to create account"
    );
  }
}

/* =========================================================
   LOGOUT
   ========================================================= */

async function logout(request) {
  const token = bearer(request);

  if (!token) {
    return ok({
      logged_out: true
    });
  }

  try {
    if (
      await tableExists(
        "sessions"
      )
    ) {
      const tokenHash =
        hashToken(token);

      await sql`
        DELETE FROM sessions
        WHERE token = ${tokenHash}
           OR token = ${token}
      `;
    }
  } catch {}

  try {
    if (
      await columnExists(
        "users",
        "session_token"
      )
    ) {
      await sql`
        UPDATE users
        SET session_token = NULL
        WHERE session_token = ${token}
      `;
    }
  } catch {}

  return ok({
    logged_out: true
  });
}

/* =========================================================
   PROFILE / CUSTOMER DATA
   ========================================================= */

function publicUser(user) {
  if (!user) return null;

  const kycStatus =
    normalizeKycStatus(user);

  const approved =
    accountApproved(user);

  const verified =
    emailVerified(user);

  return {
    id: user.id,
    email: user.email ?? "",
    full_name:
      user.full_name ??
      user.fullName ??
      user.name ??
      "",
    first_name:
      user.first_name ??
      user.firstName ??
      "",
    last_name:
      user.last_name ??
      user.lastName ??
      "",
    phone:
      user.phone ??
      user.phone_number ??
      "",
    country:
      user.country ??
      "",
    account_approved:
      approved,
    accountApproved:
      approved,
    email_verified:
      verified,
    emailVerified:
      verified,
    kyc_status:
      kycStatus,
    kycStatus,
    kyc_approved:
      kycApproved(user),
    kycApproved:
      kycApproved(user),
    status:
      user.status ??
      user.account_status ??
      "pending",
    created_at:
      user.created_at ??
      null,
    updated_at:
      user.updated_at ??
      null
  };
}

/* =========================================================
   WITHDRAWAL ACCOUNT HELPERS
   ========================================================= */

async function withdrawalTable() {
  return firstExistingTable([
    "withdrawal_accounts",
    "withdraw_accounts",
    "bank_accounts",
    "customer_withdrawal_accounts"
  ]);
}

async function getWithdrawalAccount(userId) {
  const table =
    await withdrawalTable();

  if (!table) return null;

  try {
    const rows = await sql`
      SELECT *
      FROM ${sql(table)}
      WHERE user_id = ${userId}
      ORDER BY updated_at DESC NULLS LAST,
               created_at DESC NULLS LAST
      LIMIT 1
    `;

    return rows[0] || null;
  } catch {
    return null;
  }
}

function normalizeWithdrawalAccount(row) {
  if (!row) return null;

  return {
    id: row.id ?? null,
    user_id: row.user_id ?? null,
    bank_name:
      row.bank_name ??
      row.bank ??
      "",
    account_name:
      row.account_name ??
      row.account_holder_name ??
      row.holder_name ??
      "",
    account_number:
      row.account_number ??
      row.account_no ??
      "",
    routing_number:
      row.routing_number ??
      row.routing_no ??
      "",
    sort_code:
      row.sort_code ??
      "",
    country:
      row.country ??
      "",
    currency:
      row.currency ??
      "USD",
    created_at:
      row.created_at ??
      null,
    updated_at:
      row.updated_at ??
      null
  };
}

/* =========================================================
   KYC APPLICATION
   ========================================================= */

async function submitKyc(user, body) {
  const table =
    await firstExistingTable([
      "kyc_submissions",
      "kyc_requests",
      "customer_kyc",
      "kyc"
    ]);

  if (!table) {
    return bad(
      500,
      "KYC storage is not configured"
    );
  }

  const documentType =
    body.document_type ??
    body.documentType ??
    "";

  const documentNumber =
    body.document_number ??
    body.documentNumber ??
    "";

  const country =
    body.country ??
    user.country ??
    "";

  const fullName =
    body.full_name ??
    body.fullName ??
    user.full_name ??
    "";

  try {
    const hasStatus =
      await columnExists(
        table,
        "status"
      );

    const hasKycStatus =
      await columnExists(
        table,
        "kyc_status"
      );

    const statusColumn =
      hasKycStatus
        ? "kyc_status"
        : hasStatus
          ? "status"
          : null;

    if (statusColumn) {
      const rows =
        await sql`
          INSERT INTO ${sql(table)}
            (
              user_id,
              ${sql(statusColumn)},
              document_type,
              document_number,
              country,
              full_name,
              created_at,
              updated_at
            )
          VALUES
            (
              ${user.id},
              'submitted',
              ${documentType},
              ${documentNumber},
              ${country},
              ${fullName},
              NOW(),
              NOW()
            )
          RETURNING *
        `;

      return ok({
        submission:
          rows[0] || null,
        kyc_status:
          "submitted"
      });
    }

    const rows =
      await sql`
        INSERT INTO ${sql(table)}
          (
            user_id,
            document_type,
            document_number,
            country,
            full_name,
            created_at,
            updated_at
          )
        VALUES
          (
            ${user.id},
            ${documentType},
            ${documentNumber},
            ${country},
            ${fullName},
            NOW(),
            NOW()
          )
        RETURNING *
      `;

    return ok({
      submission:
        rows[0] || null,
      kyc_status:
        "submitted"
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to submit KYC"
    );
  }
}

/* =========================================================
   ACCOUNT / USER KYC REFRESH
   ========================================================= */

async function refreshUserFromDatabase(user) {
  if (!user?.id) return user;

  const fresh =
    await getUserById(user.id);

  if (!fresh) {
    return user;
  }

  return fresh;
}

async function resolveKycFromAllSources(user) {
  const fresh =
    await refreshUserFromDatabase(
      user
    );

  let status =
    normalizeKycStatus(fresh);

  /*
    Check dedicated KYC records too.

    This is important because the admin page may approve
    KYC in a dedicated table rather than the users table.
  */

  const table =
    await firstExistingTable([
      "kyc_submissions",
      "kyc_requests",
      "customer_kyc",
      "kyc"
    ]);

  if (table) {
    try {
      const hasKycStatus =
        await columnExists(
          table,
          "kyc_status"
        );

      const hasStatus =
        await columnExists(
          table,
          "status"
        );

      let rows = [];

      if (hasKycStatus) {
        rows = await sql`
          SELECT *
          FROM ${sql(table)}
          WHERE user_id = ${fresh.id}
          ORDER BY updated_at DESC NULLS LAST,
                   created_at DESC NULLS LAST
          LIMIT 1
        `;
      } else if (hasStatus) {
        rows = await sql`
          SELECT *
          FROM ${sql(table)}
          WHERE user_id = ${fresh.id}
          ORDER BY updated_at DESC NULLS LAST,
                   created_at DESC NULLS LAST
          LIMIT 1
        `;
      }

      const kyc = rows[0];

      if (kyc) {
        const dedicated =
          String(
            kyc.kyc_status ??
            kyc.status ??
            ""
          )
            .trim()
            .toLowerCase();

        if (
          dedicated === "approved" ||
          dedicated === "verified" ||
          dedicated === "complete" ||
          dedicated === "completed"
        ) {
          status = "approved";
        } else if (
          status !== "approved" &&
          (
            dedicated === "rejected" ||
            dedicated === "declined"
          )
        ) {
          status = "rejected";
        } else if (
          status === "pending" &&
          dedicated === "submitted"
        ) {
          status = "submitted";
        }
      }
    } catch {
      /* users table remains authoritative fallback */
    }
  }

  return {
    user: fresh,
    status
  };
}

/* =========================================================
   REQUEST ROUTES
   ========================================================= */

async function routeMe(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth.error;
  }

  const user =
    await refreshUserFromDatabase(
      auth.user
    );

  const kyc =
    await resolveKycFromAllSources(
      user
    );

  const wallets =
    await synchronizeWalletRepresentations(
      user.id
    );

  const withdrawal =
    await getWithdrawalAccount(
      user.id
    );

  return ok({
    user: {
      ...publicUser(user),
      kyc_status:
        kyc.status,
      kycStatus:
        kyc.status,
      kyc_approved:
        kyc.status === "approved",
      kycApproved:
        kyc.status === "approved"
    },
    wallets: {
      main:
        wallets.main,
      mainWallet:
        wallets.main,
      profit:
        wallets.profit,
      profitWallet:
        wallets.profit,
      total:
        wallets.total,
      balance:
        wallets.main
    },
    withdrawal_account:
      normalizeWithdrawalAccount(
        withdrawal
      )
  });
}

async function routeWallets(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth.error;
  }

  const user =
    await refreshUserFromDatabase(
      auth.user
    );

  const wallets =
    await synchronizeWalletRepresentations(
      user.id
    );

  const rows =
    await getWalletRows(
      user.id
    );

  return ok({
    wallets: rows,
    mainWallet:
      wallets.main,
    main_wallet:
      wallets.main,
    profitWallet:
      wallets.profit,
    profit_wallet:
      wallets.profit,
    totalBalance:
      wallets.total,
    total_balance:
      wallets.total,
    balance:
      wallets.main
  });
}

async function routeTransactions(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth.error;
  }

  const user =
    await refreshUserFromDatabase(
      auth.user
    );

  const table =
    await transactionTable();

  if (!table) {
    return ok({
      transactions: []
    });
  }

  const limit =
    cleanLimit(
      new URL(request.url)
        .searchParams
        .get("limit"),
      100
    );

  try {
    const rows = await sql`
      SELECT *
      FROM ${sql(table)}
      WHERE user_id = ${user.id}
      ORDER BY created_at DESC NULLS LAST
      LIMIT ${limit}
    `;

    return ok({
      transactions:
        rows.map(
          normalizeTransaction
        )
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to load transactions"
    );
  }
}

/* =========================================================
   DEPOSIT
   ========================================================= */

async function routeDeposit(request) {
  const auth =
    await requireApprovedUser(request);

  if (auth.error) {
    return auth.error;
  }

  const body =
    await jsonBody(request);

  const amount =
    numberValue(
      body.amount ??
      body.value
    );

  if (amount <= 0) {
    return bad(
      400,
      "Enter a valid deposit amount"
    );
  }

  const reference =
    String(
      body.reference ??
      body.reference_number ??
      ""
    ).trim();

  const description =
    String(
      body.description ??
      body.note ??
      "Deposit request"
    ).trim();

  const requestsTable =
    await firstExistingTable([
      "deposit_requests",
      "deposit_request",
      "funding_requests",
      "transactions"
    ]);

  if (!requestsTable) {
    return bad(
      500,
      "Deposit request storage is not configured"
    );
  }

  try {
    if (
      requestsTable ===
      "transactions"
    ) {
      const rows =
        await sql`
          INSERT INTO transactions
            (
              user_id,
              type,
              amount,
              status,
              description,
              reference,
              created_at
            )
          VALUES
            (
              ${auth.user.id},
              'deposit',
              ${amount},
              'pending',
              ${description},
              ${reference},
              NOW()
            )
          RETURNING *
        `;

      return ok({
        request:
          rows[0] || null,
        status:
          "pending"
      });
    }

    const rows =
      await sql`
        INSERT INTO ${sql(requestsTable)}
          (
            user_id,
            amount,
            type,
            status,
            description,
            reference,
            created_at
          )
        VALUES
          (
            ${auth.user.id},
            ${amount},
            'deposit',
            'pending',
            ${description},
            ${reference},
            NOW()
          )
        RETURNING *
      `;

    return ok({
      request:
        rows[0] || null,
      status:
        "pending"
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to create deposit request"
    );
  }
}

/* =========================================================
   SEND
   ========================================================= */

async function routeSend(request) {
  const auth =
    await requireApprovedUser(request);

  if (auth.error) {
    return auth.error;
  }

  const body =
    await jsonBody(request);

  const amount =
    numberValue(
      body.amount
    );

  if (amount <= 0) {
    return bad(
      400,
      "Enter a valid amount"
    );
  }

  const recipient =
    normalizeEmail(
      body.recipient_email ??
      body.recipientEmail ??
      body.email ??
      ""
    );

  if (!recipient) {
    return bad(
      400,
      "Recipient email is required"
    );
  }

  const senderWallet =
    await getCustomerWallet(
      auth.user.id
    );

  if (
    amount >
    senderWallet.main
  ) {
    return bad(
      400,
      "Insufficient balance",
      {
        code:
          "INSUFFICIENT_BALANCE",
        balance:
          senderWallet.main,
        available_balance:
          senderWallet.main
      }
    );
  }

  const recipientUser =
    await getUserByEmail(
      recipient
    );

  if (!recipientUser) {
    return bad(
      404,
      "Recipient account not found"
    );
  }

  if (
    !accountApproved(
      recipientUser
    )
  ) {
    return bad(
      400,
      "Recipient account is not approved"
    );
  }

  const recipientWallet =
    await getCustomerWallet(
      recipientUser.id
    );

  const senderMain =
    await ensureWallet(
      auth.user.id,
      "main"
    );

  const recipientMain =
    await ensureWallet(
      recipientUser.id,
      "main"
    );

  if (
    !senderMain ||
    !recipientMain
  ) {
    return bad(
      500,
      "Wallet configuration is unavailable"
    );
  }

  try {
    const senderBalance =
      walletAmount(
        senderMain
      );

    const recipientBalance =
      walletAmount(
        recipientMain
      );

    if (
      senderBalance <
      amount
    ) {
      return bad(
        400,
        "Insufficient balance",
        {
          code:
            "INSUFFICIENT_BALANCE",
          balance:
            senderBalance
        }
      );
    }

    await sql`BEGIN`;

    const senderTable =
      senderMain.__table ||
      "wallets";

    const recipientTable =
      recipientMain.__table ||
      "wallets";

    const balanceColumn =
      await columnExists(
        senderTable,
        "balance"
      );

    if (balanceColumn) {
      await sql`
        UPDATE ${sql(senderTable)}
        SET balance =
          ${senderBalance - amount}
        WHERE id = ${senderMain.id}
      `;

      await sql`
        UPDATE ${sql(recipientTable)}
        SET balance =
          ${recipientBalance + amount}
        WHERE id = ${recipientMain.id}
      `;
    } else {
      await sql`
        UPDATE ${sql(senderTable)}
        SET amount =
          ${senderBalance - amount}
        WHERE id = ${senderMain.id}
      `;

      await sql`
        UPDATE ${sql(recipientTable)}
        SET amount =
          ${recipientBalance + amount}
        WHERE id = ${recipientMain.id}
      `;
    }

    const transactionsExist =
      await tableExists(
        "transactions"
      );

    if (transactionsExist) {
      await sql`
        INSERT INTO transactions
          (
            user_id,
            type,
            amount,
            status,
            description,
            created_at
          )
        VALUES
          (
            ${auth.user.id},
            'send',
            ${amount},
            'completed',
            ${`Sent to ${recipient}`},
            NOW()
          )
      `;

      await sql`
        INSERT INTO transactions
          (
            user_id,
            type,
            amount,
            status,
            description,
            created_at
          )
        VALUES
          (
            ${recipientUser.id},
            'receive',
            ${amount},
            'completed',
            ${`Received from ${auth.user.email}`},
            NOW()
          )
      `;
    }

    await sql`COMMIT`;

    return ok({
      status:
        "completed",
      amount,
      recipient,
      balance:
        senderBalance -
        amount
    });
  } catch (error) {
    try {
      await sql`ROLLBACK`;
    } catch {}

    return bad(
      500,
      error?.message ||
        "Unable to complete transfer"
    );
  }
}

/* =========================================================
   WITHDRAWAL
   ========================================================= */

async function saveWithdrawalAccount(
  user,
  body
) {
  const table =
    await withdrawalTable();

  if (!table) {
    return bad(
      500,
      "Withdrawal account storage is not configured"
    );
  }

  const bankName =
    String(
      body.bank_name ??
      body.bankName ??
      body.bank ??
      ""
    ).trim();

  const accountName =
    String(
      body.account_name ??
      body.accountName ??
      body.account_holder_name ??
      ""
    ).trim();

  const accountNumber =
    String(
      body.account_number ??
      body.accountNumber ??
      body.account_no ??
      ""
    ).trim();

  if (
    !bankName ||
    !accountName ||
    !accountNumber
  ) {
    return bad(
      400,
      "Bank name, account name and account number are required"
    );
  }

  try {
    const existing =
      await getWithdrawalAccount(
        user.id
      );

    if (existing) {
      const hasBank =
        await columnExists(
          table,
          "bank_name"
        );

      const hasName =
        await columnExists(
          table,
          "account_name"
        );

      const hasNumber =
        await columnExists(
          table,
          "account_number"
        );

      if (hasBank) {
        await sql`
          UPDATE ${sql(table)}
          SET bank_name =
            ${bankName}
          WHERE id =
            ${existing.id}
        `;
      }

      if (hasName) {
        await sql`
          UPDATE ${sql(table)}
          SET account_name =
            ${accountName}
          WHERE id =
            ${existing.id}
        `;
      }

      if (hasNumber) {
        await sql`
          UPDATE ${sql(table)}
          SET account_number =
            ${accountNumber}
          WHERE id =
            ${existing.id}
        `;
      }

      if (
        await columnExists(
          table,
          "updated_at"
        )
      ) {
        await sql`
          UPDATE ${sql(table)}
          SET updated_at =
            NOW()
          WHERE id =
            ${existing.id}
        `;
      }

      return ok({
        withdrawal_account:
          await getWithdrawalAccount(
            user.id
          )
      });
    }

    const rows =
      await sql`
        INSERT INTO ${sql(table)}
          (
            user_id,
            bank_name,
            account_name,
            account_number,
            created_at,
            updated_at
          )
        VALUES
          (
            ${user.id},
            ${bankName},
            ${accountName},
            ${accountNumber},
            NOW(),
            NOW()
          )
        RETURNING *
      `;

    return ok({
      withdrawal_account:
        rows[0] || null
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to save withdrawal account"
    );
  }
}

async function routeWithdrawalAccount(
  request
) {
  const auth =
    await requireApprovedUser(request);

  if (auth.error) {
    return auth.error;
  }

  if (
    request.method === "GET"
  ) {
    const account =
      await getWithdrawalAccount(
        auth.user.id
      );

    return ok({
      withdrawal_account:
        normalizeWithdrawalAccount(
          account
        )
    });
  }

  if (
    request.method === "POST" ||
    request.method === "PUT" ||
    request.method === "PATCH"
  ) {
    const body =
      await jsonBody(request);

    return saveWithdrawalAccount(
      auth.user,
      body
    );
  }

  return bad(
    405,
    "Method not allowed"
  );
}

async function routeWithdraw(request) {
  const auth =
    await requireApprovedUser(request);

  if (auth.error) {
    return auth.error;
  }

  const body =
    await jsonBody(request);

  const amount =
    numberValue(
      body.amount
    );

  if (amount <= 0) {
    return bad(
      400,
      "Enter a valid withdrawal amount"
    );
  }

  const wallet =
    await getCustomerWallet(
      auth.user.id
    );

  if (
    amount >
    wallet.main
  ) {
    return bad(
      400,
      "Insufficient balance",
      {
        code:
          "INSUFFICIENT_BALANCE",
        balance:
          wallet.main,
        available_balance:
          wallet.main
      }
    );
  }

  let account =
    await getWithdrawalAccount(
      auth.user.id
    );

  /*
    If no withdrawal account exists, explicitly tell the
    customer to complete it. The dashboard can use this
    response for the one-time redirect.
  */
  if (!account) {
    return bad(
      409,
      "Withdrawal account details are required",
      {
        code:
          "WITHDRAWAL_ACCOUNT_REQUIRED",
        redirect:
          "/dashboard.html#withdrawal-account"
      }
    );
  }

  const table =
    await transactionTable();

  if (!table) {
    return bad(
      500,
      "Withdrawal transaction storage is not configured"
    );
  }

  try {
    const rows =
      await sql`
        INSERT INTO ${sql(table)}
          (
            user_id,
            type,
            amount,
            status,
            description,
            created_at
          )
        VALUES
          (
            ${auth.user.id},
            'withdrawal',
            ${amount},
            'pending',
            'Withdrawal request',
            NOW()
          )
        RETURNING *
      `;

    return ok({
      request:
        normalizeTransaction(
          rows[0]
        ),
      status:
        "pending",
      withdrawal_account:
        normalizeWithdrawalAccount(
          account
        )
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to create withdrawal request"
    );
  }
}

/* =========================================================
   KYC ROUTE
   ========================================================= */

async function routeKyc(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth.error;
  }

  const fresh =
    await refreshUserFromDatabase(
      auth.user
    );

  const current =
    await resolveKycFromAllSources(
      fresh
    );

  if (
    request.method === "GET"
  ) {
    return ok({
      kyc_status:
        current.status,
      kycStatus:
        current.status,
      approved:
        current.status ===
        "approved",
      kyc_approved:
        current.status ===
        "approved",
      kycApproved:
        current.status ===
        "approved"
    });
  }

  if (
    request.method === "POST"
  ) {
    if (
      current.status ===
      "approved"
    ) {
      return ok({
        message:
          "KYC is already approved",
        kyc_status:
          "approved",
        approved:
          true
      });
    }

    const body =
      await jsonBody(request);

    return submitKyc(
      current.user,
      body
    );
  }

  return bad(
    405,
    "Method not allowed"
  );
}

/* =========================================================
   PROFILE
   ========================================================= */

async function routeProfile(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth.error;
  }

  const fresh =
    await refreshUserFromDatabase(
      auth.user
    );

  if (
    request.method === "GET"
  ) {
    return ok({
      profile:
        publicUser(fresh)
    });
  }

  if (
    request.method === "PUT" ||
    request.method === "PATCH"
  ) {
    const body =
      await jsonBody(request);

    const fullName =
      body.full_name ??
      body.fullName ??
      null;

    const phone =
      body.phone ??
      body.phone_number ??
      null;

    const country =
      body.country ??
      null;

    try {
      if (
        fullName !== null &&
        await columnExists(
          "users",
          "full_name"
        )
      ) {
        await sql`
          UPDATE users
          SET full_name =
            ${String(
              fullName
            ).trim()}
          WHERE id =
            ${fresh.id}
        `;
      }

      if (
        phone !== null &&
        await columnExists(
          "users",
          "phone"
        )
      ) {
        await sql`
          UPDATE users
          SET phone =
            ${String(
              phone
            ).trim()}
          WHERE id =
            ${fresh.id}
        `;
      }

      if (
        country !== null &&
        await columnExists(
          "users",
          "country"
        )
      ) {
        await sql`
          UPDATE users
          SET country =
            ${String(
              country
            ).trim()}
          WHERE id =
            ${fresh.id}
        `;
      }

      const updated =
        await getUserById(
          fresh.id
        );

      return ok({
        profile:
          publicUser(
            updated
          )
      });
    } catch (error) {
      return bad(
        500,
        error?.message ||
          "Unable to update profile"
      );
    }
  }

  return bad(
    405,
    "Method not allowed"
  );
}

/* =========================================================
   ADMIN AUTH
   ========================================================= */

function isAdmin(user) {
  if (!user) return false;

  return Boolean(
    user.is_admin === true ||
    user.isAdmin === true ||
    user.role === "admin" ||
    user.user_role === "admin" ||
    user.account_type === "admin"
  );
}

async function requireAdmin(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth;
  }

  if (!isAdmin(auth.user)) {
    return {
      user: auth.user,
      error: bad(
        403,
        "Administrator access required"
      )
    };
  }

  return auth;
}

/* =========================================================
   ADMIN ACCOUNT APPROVAL
   ========================================================= */

async function approveAccount(
  request,
  userId,
  approved
) {
  const auth =
    await requireAdmin(request);

  if (auth.error) {
    return auth.error;
  }

  const user =
    await getUserById(
      userId
    );

  if (!user) {
    return bad(
      404,
      "Customer account not found"
    );
  }

  try {
    if (
      await columnExists(
        "users",
        "account_approved"
      )
    ) {
      await sql`
        UPDATE users
        SET account_approved =
          ${approved}
        WHERE id =
          ${userId}
      `;
    }

    if (
      await columnExists(
        "users",
        "approved"
      )
    ) {
      await sql`
        UPDATE users
        SET approved =
          ${approved}
        WHERE id =
          ${userId}
      `;
    }

    if (
      await columnExists(
        "users",
        "is_approved"
      )
    ) {
      await sql`
        UPDATE users
        SET is_approved =
          ${approved}
        WHERE id =
          ${userId}
      `;
    }

    if (
      await columnExists(
        "users",
        "status"
      )
    ) {
      await sql`
        UPDATE users
        SET status =
          ${
            approved
              ? "approved"
              : "pending"
          }
        WHERE id =
          ${userId}
      `;
    }

    /*
      IMPORTANT:
      Approval is also the temporary email-verification
      mechanism.
    */

    if (
      approved &&
      await columnExists(
        "users",
        "email_verified"
      )
    ) {
      await sql`
        UPDATE users
        SET email_verified =
          TRUE
        WHERE id =
          ${userId}
      `;
    }

    if (
      approved &&
      await columnExists(
        "users",
        "emailVerified"
      )
    ) {
      await sql`
        UPDATE users
        SET "emailVerified" =
          TRUE
        WHERE id =
          ${userId}
      `;
    }

    if (
      approved &&
      await columnExists(
        "users",
        "is_email_verified"
      )
    ) {
      await sql`
        UPDATE users
        SET is_email_verified =
          TRUE
        WHERE id =
          ${userId}
      `;
    }

    const updated =
      await getUserById(
        userId
      );

    return ok({
      user:
        publicUser(
          updated
        ),
      account_approved:
        approved,
      email_verified:
        approved
          ? true
          : emailVerified(
              updated
            )
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to update account approval"
    );
  }
}

/* =========================================================
   ADMIN KYC APPROVAL
   ========================================================= */

async function adminKycUpdate(
  request,
  userId,
  status
) {
  const auth =
    await requireAdmin(request);

  if (auth.error) {
    return auth.error;
  }

  const user =
    await getUserById(
      userId
    );

  if (!user) {
    return bad(
      404,
      "Customer account not found"
    );
  }

  const normalized =
    String(status)
      .trim()
      .toLowerCase();

  const approved =
    normalized === "approved" ||
    normalized === "verified";

  try {
    /*
      First update users table wherever the installation
      contains a KYC field.
    */

    if (
      await columnExists(
        "users",
        "kyc_status"
      )
    ) {
      await sql`
        UPDATE users
        SET kyc_status =
          ${
            approved
              ? "approved"
              : normalized
          }
        WHERE id =
          ${userId}
      `;
    }

    if (
      approved &&
      await columnExists(
        "users",
        "kyc_verified"
      )
    ) {
      await sql`
        UPDATE users
        SET kyc_verified =
          TRUE
        WHERE id =
          ${userId}
      `;
    }

    if (
      approved &&
      await columnExists(
        "users",
        "kyc_approved"
      )
    ) {
      await sql`
        UPDATE users
        SET kyc_approved =
          TRUE
        WHERE id =
          ${userId}
      `;
    }

    if (
      !approved &&
      await columnExists(
        "users",
        "kyc_verified"
      )
    ) {
      await sql`
        UPDATE users
        SET kyc_verified =
          FALSE
        WHERE id =
          ${userId}
      `;
    }

    /*
      Then synchronize the dedicated KYC record if one exists.
    */

    const table =
      await firstExistingTable([
        "kyc_submissions",
        "kyc_requests",
        "customer_kyc",
        "kyc"
      ]);

    if (table) {
      const hasKycStatus =
        await columnExists(
          table,
          "kyc_status"
        );

      const hasStatus =
        await columnExists(
          table,
          "status"
        );

      const hasApproved =
        await columnExists(
          table,
          "approved"
        );

      const existingRows =
        await sql`
          SELECT *
          FROM ${sql(table)}
          WHERE user_id =
            ${userId}
          ORDER BY created_at DESC NULLS LAST
          LIMIT 1
        `;

      if (
        existingRows[0]
      ) {
        if (hasKycStatus) {
          await sql`
            UPDATE ${sql(table)}
            SET kyc_status =
              ${
                approved
                  ? "approved"
                  : normalized
              }
            WHERE id =
              ${existingRows[0].id}
          `;
        }

        if (
          hasStatus &&
          !hasKycStatus
        ) {
          await sql`
            UPDATE ${sql(table)}
            SET status =
              ${
                approved
                  ? "approved"
                  : normalized
              }
            WHERE id =
              ${existingRows[0].id}
          `;
        }

        if (hasApproved) {
          await sql`
            UPDATE ${sql(table)}
            SET approved =
              ${approved}
            WHERE id =
              ${existingRows[0].id}
          `;
        }
      }
    }

    const updated =
      await getUserById(
        userId
      );

    const finalKyc =
      await resolveKycFromAllSources(
        updated
      );

    return ok({
      user:
        publicUser(
          updated
        ),
      kyc_status:
        finalKyc.status,
      kyc_approved:
        finalKyc.status ===
        "approved"
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to update KYC"
    );
  }
}

/* =========================================================
   ADMIN WALLET ADJUSTMENT
   ========================================================= */

async function adminAdjustWallet(
  request,
  userId
) {
  const auth =
    await requireAdmin(request);

  if (auth.error) {
    return auth.error;
  }

  const body =
    await jsonBody(request);

  const action =
    String(
      body.action ??
      body.type ??
      "credit"
    )
      .trim()
      .toLowerCase();

  const amount =
    numberValue(
      body.amount
    );

  const description =
    String(
      body.description ??
      body.note ??
      "Admin wallet adjustment"
    ).trim();

  if (amount <= 0) {
    return bad(
      400,
      "Amount must be greater than zero"
    );
  }

  const user =
    await getUserById(
      userId
    );

  if (!user) {
    return bad(
      404,
      "Customer account not found"
    );
  }

  /*
    Prefer the SECURITY DEFINER RPC when available.
    The customer wallet must correspond with the same wallet
    the admin adjusted.
  */

  try {
    const rpcExists =
      await sql`
        SELECT EXISTS (
          SELECT 1
          FROM pg_proc p
          JOIN pg_namespace n
            ON n.oid =
              p.pronamespace
          WHERE n.nspname =
            'public'
            AND p.proname =
              'admin_adjust_wallet'
        ) AS exists
      `;

    if (
      rpcExists[0]?.exists
    ) {
      const wallet =
        await ensureWallet(
          userId,
          "main"
        );

      if (!wallet?.id) {
        return bad(
          500,
          "Customer main wallet not found"
        );
      }

      const rpcRows =
        await sql`
          SELECT *
          FROM public.admin_adjust_wallet(
            ${wallet.id},
            ${action},
            ${amount},
            ${description}
          )
        `;

      const refreshed =
        await synchronizeWalletRepresentations(
          userId
        );

      return ok({
        result:
          rpcRows[0] || null,
        wallet: {
          main:
            refreshed.main,
          profit:
            refreshed.profit,
          total:
            refreshed.total
        }
      });
    }
  } catch {}

  const wallet =
    await getCustomerWallet(
      userId
    );

  const current =
    wallet.main;

  let next;

  if (
    action === "debit" ||
    action === "subtract" ||
    action === "deduct" ||
    action === "withdraw"
  ) {
    next =
      current - amount;

    if (next < 0) {
      return bad(
        400,
        "Insufficient wallet balance"
      );
    }
  } else {
    next =
      current + amount;
  }

  const mainWallet =
    await ensureWallet(
      userId,
      "main"
    );

  if (!mainWallet) {
    return bad(
      500,
      "Customer main wallet not found"
    );
  }

  try {
    const table =
      mainWallet.__table ||
      "wallets";

    const hasBalance =
      await columnExists(
        table,
        "balance"
      );

    if (hasBalance) {
      await sql`
        UPDATE ${sql(table)}
        SET balance =
          ${next}
        WHERE id =
          ${mainWallet.id}
      `;
    } else {
      await sql`
        UPDATE ${sql(table)}
        SET amount =
          ${next}
        WHERE id =
          ${mainWallet.id}
      `;
    }

    const transactionsExist =
      await tableExists(
        "transactions"
      );

    if (transactionsExist) {
      await sql`
        INSERT INTO transactions
          (
            user_id,
            type,
            amount,
            status,
            description,
            created_at
          )
        VALUES
          (
            ${userId},
            ${action},
            ${amount},
            'completed',
            ${description},
            NOW()
          )
      `;
    }

    const refreshed =
      await synchronizeWalletRepresentations(
        userId
      );

    return ok({
      wallet: {
        main:
          refreshed.main,
        profit:
          refreshed.profit,
        total:
          refreshed.total
      },
      amount,
      action
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to adjust wallet"
    );
  }
}

/* =========================================================
   ADMIN CUSTOMER DETAILS
   ========================================================= */

async function adminCustomer(
  request,
  userId
) {
  const auth =
    await requireAdmin(request);

  if (auth.error) {
    return auth.error;
  }

  const user =
    await getUserById(
      userId
    );

  if (!user) {
    return bad(
      404,
      "Customer not found"
    );
  }

  const kyc =
    await resolveKycFromAllSources(
      user
    );

  const wallets =
    await synchronizeWalletRepresentations(
      userId
    );

  const transactionsTable =
    await transactionTable();

  let transactions = [];

  if (transactionsTable) {
    try {
      const rows =
        await sql`
          SELECT *
          FROM ${sql(transactionsTable)}
          WHERE user_id =
            ${userId}
          ORDER BY created_at DESC NULLS LAST
          LIMIT 100
        `;

      transactions =
        rows.map(
          normalizeTransaction
        );
    } catch {}
  }

  return ok({
    customer:
      publicUser(user),
    kyc_status:
      kyc.status,
    wallets: {
      main:
        wallets.main,
      profit:
        wallets.profit,
      total:
        wallets.total
    },
    transactions
  });
}

/* =========================================================
   CHAT HELPERS
   ========================================================= */

async function chatTable() {
  return firstExistingTable([
    "chat_messages",
    "customer_chat",
    "messages",
    "support_messages"
  ]);
}

function normalizeChatMessage(row) {
  return {
    id:
      row?.id ??
      null,
    user_id:
      row?.user_id ??
      row?.customer_id ??
      null,
    sender_id:
      row?.sender_id ??
      row?.user_id ??
      null,
    sender_role:
      row?.sender_role ??
      row?.role ??
      "customer",
    message:
      row?.message ??
      row?.content ??
      row?.text ??
      "",
    image_url:
      row?.image_url ??
      row?.attachment_url ??
      null,
    created_at:
      row?.created_at ??
      new Date().toISOString()
  };
}

async function routeChat(request) {
  const auth =
    await requireUser(request);

  if (auth.error) {
    return auth.error;
  }

  const table =
    await chatTable();

  if (!table) {
    return bad(
      500,
      "Customer chat storage is not configured"
    );
  }

  if (
    request.method === "GET"
  ) {
    try {
      const hasUser =
        await columnExists(
          table,
          "user_id"
        );

      const hasCustomer =
        await columnExists(
          table,
          "customer_id"
        );

      if (hasUser) {
        const rows =
          await sql`
            SELECT *
            FROM ${sql(table)}
            WHERE user_id =
              ${auth.user.id}
            ORDER BY created_at ASC NULLS LAST
            LIMIT 500
          `;

        return ok({
          messages:
            rows.map(
              normalizeChatMessage
            )
        });
      }

      if (hasCustomer) {
        const rows =
          await sql`
            SELECT *
            FROM ${sql(table)}
            WHERE customer_id =
              ${auth.user.id}
            ORDER BY created_at ASC NULLS LAST
            LIMIT 500
          `;

        return ok({
          messages:
            rows.map(
              normalizeChatMessage
            )
        });
      }

      return bad(
        500,
        "Chat table has no customer reference column"
      );
    } catch (error) {
      return bad(
        500,
        error?.message ||
          "Unable to load chat"
      );
    }
  }

  if (
    request.method === "POST"
  ) {
    if (
      !customerCanAct(
        auth.user
      )
    ) {
      return bad(
        403,
        "Account approval is required before sending messages",
        {
          code:
            "ACCOUNT_NOT_APPROVED"
        }
      );
    }

    const body =
      await jsonBody(request);

    const message =
      String(
        body.message ??
        body.content ??
        body.text ??
        ""
      ).trim();

    const imageUrl =
      body.image_url ??
      body.imageUrl ??
      body.attachment_url ??
      null;

    if (
      !message &&
      !imageUrl
    ) {
      return bad(
        400,
        "Message or image is required"
      );
    }

    try {
      const hasUser =
        await columnExists(
          table,
          "user_id"
        );

      const hasCustomer =
        await columnExists(
          table,
          "customer_id"
        );

      const hasMessage =
        await columnExists(
          table,
          "message"
        );

      const hasContent =
        await columnExists(
          table,
          "content"
        );

      const hasImage =
        await columnExists(
          table,
          "image_url"
        );

      if (
        hasUser &&
        hasMessage
      ) {
        const rows =
          await sql`
            INSERT INTO ${sql(table)}
              (
                user_id,
                message,
                image_url,
                sender_role,
                created_at
              )
            VALUES
              (
                ${auth.user.id},
                ${message},
                ${imageUrl},
                'customer',
                NOW()
              )
            RETURNING *
          `;

        return ok({
          message:
            normalizeChatMessage(
              rows[0]
            )
        });
      }

      if (
        hasCustomer &&
        hasMessage
      ) {
        const rows =
          await sql`
            INSERT INTO ${sql(table)}
              (
                customer_id,
                message,
                image_url,
                sender_role,
                created_at
              )
            VALUES
              (
                ${auth.user.id},
                ${message},
                ${imageUrl},
                'customer',
                NOW()
              )
            RETURNING *
          `;

        return ok({
          message:
            normalizeChatMessage(
              rows[0]
            )
        });
      }

      if (
        hasUser &&
        hasContent
      ) {
        const rows =
          await sql`
            INSERT INTO ${sql(table)}
              (
                user_id,
                content,
                created_at
              )
            VALUES
              (
                ${auth.user.id},
                ${message},
                NOW()
              )
            RETURNING *
          `;

        return ok({
          message:
            normalizeChatMessage(
              rows[0]
            )
        });
      }

      return bad(
        500,
        "Chat table schema is not compatible"
      );
    } catch (error) {
      return bad(
        500,
        error?.message ||
          "Unable to send chat message"
      );
    }
  }

  return bad(
    405,
    "Method not allowed"
  );
}

/* =========================================================
   ADMIN CHAT
   ========================================================= */

async function routeAdminChat(
  request,
  userId
) {
  const auth =
    await requireAdmin(request);

  if (auth.error) {
    return auth.error;
  }

  const table =
    await chatTable();

  if (!table) {
    return bad(
      500,
      "Customer chat storage is not configured"
    );
  }

  if (
    request.method === "GET"
  ) {
    try {
      const hasUser =
        await columnExists(
          table,
          "user_id"
        );

      const hasCustomer =
        await columnExists(
          table,
          "customer_id"
        );

      if (hasUser) {
        const rows =
          await sql`
            SELECT *
            FROM ${sql(table)}
            WHERE user_id =
              ${userId}
            ORDER BY created_at ASC NULLS LAST
            LIMIT 500
          `;

        return ok({
          messages:
            rows.map(
              normalizeChatMessage
            )
        });
      }

      if (hasCustomer) {
        const rows =
          await sql`
            SELECT *
            FROM ${sql(table)}
            WHERE customer_id =
              ${userId}
            ORDER BY created_at ASC NULLS LAST
            LIMIT 500
          `;

        return ok({
          messages:
            rows.map(
              normalizeChatMessage
            )
        });
      }

      return bad(
        500,
        "Chat table has no customer reference column"
      );
    } catch (error) {
      return bad(
        500,
        error?.message ||
          "Unable to load customer chat"
      );
    }
  }

  if (
    request.method === "POST"
  ) {
    const body =
      await jsonBody(request);

    const message =
      String(
        body.message ??
        body.content ??
        body.text ??
        ""
      ).trim();

    const imageUrl =
      body.image_url ??
      body.imageUrl ??
      body.attachment_url ??
      null;

    if (
      !message &&
      !imageUrl
    ) {
      return bad(
        400,
        "Message or image is required"
      );
    }

    try {
      const hasUser =
        await columnExists(
          table,
          "user_id"
        );

      const hasCustomer =
        await columnExists(
          table,
          "customer_id"
        );

      const hasMessage =
        await columnExists(
          table,
          "message"
        );

      if (
        hasUser &&
        hasMessage
      ) {
        const rows =
          await sql`
            INSERT INTO ${sql(table)}
              (
                user_id,
                message,
                image_url,
                sender_role,
                created_at
              )
            VALUES
              (
                ${userId},
                ${message},
                ${imageUrl},
                'admin',
                NOW()
              )
            RETURNING *
          `;

        return ok({
          message:
            normalizeChatMessage(
              rows[0]
            )
        });
      }

      if (
        hasCustomer &&
        hasMessage
      ) {
        const rows =
          await sql`
            INSERT INTO ${sql(table)}
              (
                customer_id,
                message,
                image_url,
                sender_role,
                created_at
              )
            VALUES
              (
                ${userId},
                ${message},
                ${imageUrl},
                'admin',
                NOW()
              )
            RETURNING *
          `;

        return ok({
          message:
            normalizeChatMessage(
              rows[0]
            )
        });
      }

      return bad(
        500,
        "Chat table schema is not compatible"
      );
    } catch (error) {
      return bad(
        500,
        error?.message ||
          "Unable to send admin message"
      );
    }
  }

  return bad(
    405,
    "Method not allowed"
  );
}

/* =========================================================
   ADMIN CUSTOMER LIST
   ========================================================= */

async function routeAdminCustomers(
  request
) {
  const auth =
    await requireAdmin(request);

  if (auth.error) {
    return auth.error;
  }

  try {
    const limit =
      cleanLimit(
        new URL(request.url)
          .searchParams
          .get("limit"),
        200
      );

    const rows =
      await sql`
        SELECT *
        FROM users
        ORDER BY created_at DESC NULLS LAST
        LIMIT ${limit}
      `;

    const customers = [];

    for (const user of rows) {
      const kyc =
        await resolveKycFromAllSources(
          user
        );

      const wallets =
        await synchronizeWalletRepresentations(
          user.id
        );

      customers.push({
        ...publicUser(user),
        kyc_status:
          kyc.status,
        kyc_approved:
          kyc.status ===
          "approved",
        wallet_balance:
          wallets.main,
        main_wallet:
          wallets.main,
        profit_wallet:
          wallets.profit,
        total_balance:
          wallets.total
      });
    }

    return ok({
      customers
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to load customers"
    );
  }
}

/* =========================================================
   ADMIN TRANSACTIONS
   ========================================================= */

async function routeAdminTransactions(
  request
) {
  const auth =
    await requireAdmin(request);

  if (auth.error) {
    return auth.error;
  }

  const table =
    await transactionTable();

  if (!table) {
    return ok({
      transactions: []
    });
  }

  try {
    const limit =
      cleanLimit(
        new URL(request.url)
          .searchParams
          .get("limit"),
        200
      );

    const rows =
      await sql`
        SELECT *
        FROM ${sql(table)}
        ORDER BY created_at DESC NULLS LAST
        LIMIT ${limit}
      `;

    return ok({
      transactions:
        rows.map(
          normalizeTransaction
        )
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to load transactions"
    );
  }
}

/* =========================================================
   HEALTH
   ========================================================= */

async function routeHealth() {
  try {
    const rows =
      await sql`
        SELECT NOW() AS now
      `;

    return ok({
      database:
        true,
      timestamp:
        rows[0]?.now ??
        new Date().toISOString()
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Database unavailable",
      {
        database:
          false
      }
    );
  }
}

/* =========================================================
   ROUTER
   ========================================================= */

function pathParts(request) {
  const url =
    new URL(request.url);

  return url.pathname
    .replace(/^\/+|\/+$/g, "")
    .split("/")
    .filter(Boolean);
}

export default async function handler(
  request
) {
  if (
    request.method ===
    "OPTIONS"
  ) {
    return new Response(
      null,
      {
        status: 204,
        headers
      }
    );
  }

  const parts =
    pathParts(request);

  const path =
    "/" +
    parts.join("/");

  try {
    /*
      =======================================================
      AUTHENTICATION — LOGIN
      =======================================================
    */

    if (
      request.method === "POST" &&
      (
        path === "/login" ||
        path === "/api/login" ||
        path === "/api/auth/login" ||
        path === "/api/customer/login"
      )
    ) {
      return login(
        await jsonBody(request)
      );
    }

    /*
      =======================================================
      AUTHENTICATION — REGISTER
      =======================================================
    */

    if (
      request.method === "POST" &&
      (
        path === "/register" ||
        path === "/api/register" ||
        path === "/api/auth/register" ||
        path === "/api/customer/register"
      )
    ) {
      return register(
        await jsonBody(request)
      );
    }

    /*
      =======================================================
      AUTHENTICATION — LOGOUT
      =======================================================
    */

    if (
      request.method === "POST" &&
      (
        path === "/logout" ||
        path === "/api/logout" ||
        path === "/api/auth/logout" ||
        path === "/api/customer/logout"
      )
    ) {
      return logout(request);
    }

    /*
      Health endpoints
    */

    if (
      path === "/health" ||
      path === "/api/health"
    ) {
      return routeHealth();
    }

    /*
      Current customer
    */

    if (
      path === "/me" ||
      path === "/api/me" ||
      path === "/api/customer/me"
    ) {
      return routeMe(
        request
      );
    }

    /*
      Wallets
    */

    if (
      path === "/wallets" ||
      path === "/api/wallets" ||
      path === "/api/customer/wallets"
    ) {
      return routeWallets(
        request
      );
    }

    /*
      Transactions
    */

    if (
      path === "/transactions" ||
      path === "/api/transactions" ||
      path === "/api/customer/transactions"
    ) {
      return routeTransactions(
        request
      );
    }

    /*
      Deposit
    */

    if (
      path === "/deposit" ||
      path === "/api/deposit" ||
      path === "/api/customer/deposit"
    ) {
      return routeDeposit(
        request
      );
    }

    /*
      Send
    */

    if (
      path === "/send" ||
      path === "/api/send" ||
      path === "/api/customer/send"
    ) {
      return routeSend(
        request
      );
    }

    /*
      Withdrawal
    */

    if (
      path === "/withdraw" ||
      path === "/api/withdraw" ||
      path === "/api/customer/withdraw"
    ) {
      return routeWithdraw(
        request
      );
    }

    /*
      Withdrawal account
    */

    if (
      path ===
        "/withdrawal-account" ||
      path ===
        "/api/withdrawal-account" ||
      path ===
        "/api/customer/withdrawal-account" ||
      path ===
        "/api/profile/withdrawal-account"
    ) {
      return routeWithdrawalAccount(
        request
      );
    }

    /*
      KYC
    */

    if (
      path === "/kyc" ||
      path === "/api/kyc" ||
      path === "/api/customer/kyc"
    ) {
      return routeKyc(
        request
      );
    }

    /*
      Profile
    */

    if (
      path === "/profile" ||
      path === "/api/profile" ||
      path === "/api/customer/profile"
    ) {
      return routeProfile(
        request
      );
    }

    /*
      Customer chat
    */

    if (
      path === "/chat" ||
      path === "/api/chat" ||
      path === "/api/customer/chat"
    ) {
      return routeChat(
        request
      );
    }

    /*
      Admin customers
    */

    if (
      path ===
        "/admin/customers" ||
      path ===
        "/api/admin/customers"
    ) {
      return routeAdminCustomers(
        request
      );
    }

    /*
      Admin customer detail
    */

    if (
      (
        path ===
          "/admin/customer" ||
        path ===
          "/api/admin/customer"
      ) &&
      parts.length >= 3
    ) {
      return adminCustomer(
        request,
        parts[
          parts.length - 1
        ]
      );
    }

    /*
      Admin customer detail compatibility:
      /admin/customers/:id
    */

    if (
      (
        path.startsWith(
          "/admin/customers/"
        ) ||
        path.startsWith(
          "/api/admin/customers/"
        )
      ) &&
      parts.length >= 3
    ) {
      return adminCustomer(
        request,
        parts[
          parts.length - 1
        ]
      );
    }

    /*
      Admin wallet adjustment
    */

    if (
      path.startsWith(
        "/admin/wallet/"
      ) ||
      path.startsWith(
        "/api/admin/wallet/"
      )
    ) {
      return adminAdjustWallet(
        request,
        parts[
          parts.length - 1
        ]
      );
    }

    if (
      path.startsWith(
        "/admin/wallet-adjust/"
      ) ||
      path.startsWith(
        "/api/admin/wallet-adjust/"
      )
    ) {
      return adminAdjustWallet(
        request,
        parts[
          parts.length - 1
        ]
      );
    }

    /*
      Admin KYC
    */

    if (
      path.startsWith(
        "/admin/kyc/"
      ) ||
      path.startsWith(
        "/api/admin/kyc/"
      )
    ) {
      const body =
        await jsonBody(
          request
        );

      const userId =
        parts[
          parts.length - 1
        ];

      const status =
        body.status ??
        body.kyc_status ??
        (
          path.endsWith(
            "/approve"
          )
            ? "approved"
            : "pending"
        );

      return adminKycUpdate(
        request,
        userId,
        status
      );
    }

    if (
      path.startsWith(
        "/admin/kyc-approve/"
      ) ||
      path.startsWith(
        "/api/admin/kyc-approve/"
      )
    ) {
      return adminKycUpdate(
        request,
        parts[
          parts.length - 1
        ],
        "approved"
      );
    }

    /*
      Admin account approval
    */

    if (
      path.startsWith(
        "/admin/account/approve/"
      ) ||
      path.startsWith(
        "/api/admin/account/approve/"
      )
    ) {
      return approveAccount(
        request,
        parts[
          parts.length - 1
        ],
        true
      );
    }

    if (
      path.startsWith(
        "/admin/account/reject/"
      ) ||
      path.startsWith(
        "/api/admin/account/reject/"
      ) ||
      path.startsWith(
        "/admin/account/decline/"
      ) ||
      path.startsWith(
        "/api/admin/account/decline/"
      )
    ) {
      return approveAccount(
        request,
        parts[
          parts.length - 1
        ],
        false
      );
    }

    /*
      Admin transactions
    */

    if (
      path ===
        "/admin/transactions" ||
      path ===
        "/api/admin/transactions"
    ) {
      return routeAdminTransactions(
        request
      );
    }

    /*
      Admin chat
    */

    if (
      (
        path.startsWith(
          "/admin/chat/"
        ) ||
        path.startsWith(
          "/api/admin/chat/"
        )
      ) &&
      parts.length >= 3
    ) {
      return routeAdminChat(
        request,
        parts[
          parts.length - 1
        ]
      );
    }

    /*
      Generic customer chat compatibility
    */

    if (
      path.startsWith(
        "/admin/customer-chat/"
      ) ||
      path.startsWith(
        "/api/admin/customer-chat/"
      )
    ) {
      return routeAdminChat(
        request,
        parts[
          parts.length - 1
        ]
      );
    }

    return bad(
      404,
      "API route not found",
      {
        path
      }
    );
  } catch (error) {
    console.error(
      "INDEX.JS ERROR:",
      error
    );

    return bad(
      500,
      error?.message ||
        "Internal server error"
    );
  }
    }
