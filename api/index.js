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
   DATABASE COMPATIBILITY HELPERS
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

async function ensureKycSchema() {
  await sql`
    CREATE TABLE IF NOT EXISTS kyc_submissions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      document_type TEXT,
      document_number TEXT,
      country TEXT,
      full_name TEXT,
      notes TEXT,
      reviewed_by UUID,
      reviewed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS document_type TEXT
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS document_number TEXT
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS country TEXT
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS full_name TEXT
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS notes TEXT
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS reviewed_by UUID
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ
  `;

  await sql`
    ALTER TABLE kyc_submissions
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
  `;
}

async function ensureChatSchema() {
  await sql`
    CREATE TABLE IF NOT EXISTS support_messages (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL,
      sender_role TEXT NOT NULL DEFAULT 'customer',
      message TEXT,
      image_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;
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
   AUTH HELPERS
===================================================== */

async function findUserById(userId) {
  const rows = await sql`
    SELECT *
    FROM profiles
    WHERE id = ${userId}
    LIMIT 1
  `;

  return rows[0] || null;
}

async function findUserByEmail(email) {
  const normalized =
    normalizeEmail(email);

  const rows = await sql`
    SELECT *
    FROM profiles
    WHERE LOWER(email) = ${normalized}
    LIMIT 1
  `;

  return rows[0] || null;
}

async function findUserByUsername(username) {
  const value =
    String(username || "")
      .trim()
      .toLowerCase();

  const rows = await sql`
    SELECT *
    FROM profiles
    WHERE LOWER(username) = ${value}
    LIMIT 1
  `;

  return rows[0] || null;
}

async function getAuthUser(request) {
  const token = bearer(request);

  if (!token) {
    return null;
  }

  const tokenHash =
    hashToken(token);

  try {
    const rows = await sql`
      SELECT
        s.user_id,
        s.expires_at,
        p.*
      FROM auth_sessions s
      INNER JOIN profiles p
        ON p.id = s.user_id
      WHERE s.token_hash = ${tokenHash}
        AND s.expires_at > NOW()
      LIMIT 1
    `;

    return rows[0] || null;
  } catch {
    return null;
  }
}

async function requireUser(request) {
  const user =
    await getAuthUser(request);

  if (!user) {
    return {
      ok: false,
      status: 401,
      error: "Authentication required."
    };
  }

  return {
    ok: true,
    user
  };
}

async function requireApprovedCustomer(
  request
) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return auth;
  }

  const user =
    await findUserById(
      auth.user.id
    );

  if (!user) {
    return {
      ok: false,
      status: 404,
      error: "Customer account not found."
    };
  }

  if (
    String(user.kyc_status || "")
      .toLowerCase() !== "approved"
  ) {
    return {
      ok: false,
      status: 403,
      error:
        "KYC verification is required before you can perform this action."
    };
  }

  return {
    ok: true,
    user
  };
}

async function requireAdmin(request) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return auth;
  }

  const user =
    auth.user;

  const role =
    String(
      user.role ||
      user.user_role ||
      ""
    ).toLowerCase();

  const isAdmin =
    role === "admin" ||
    role === "super_admin" ||
    user.is_admin === true;

  if (!isAdmin) {
    return {
      ok: false,
      status: 403,
      error: "Administrator access required."
    };
  }

  return {
    ok: true,
    user
  };
}

/* =====================================================
   WALLET HELPERS
===================================================== */

async function getWallet(userId) {
  const walletTable =
    await firstExistingTable([
      "wallets",
      "customer_wallets",
      "user_wallets"
    ]);

  if (!walletTable) {
    throw new Error(
      "Wallet table not found."
    );
  }

  const rows =
    await sql.unsafe(
      `
      SELECT *
      FROM "${walletTable}"
      WHERE user_id = $1
      LIMIT 1
      `,
      [userId]
    );

  if (!rows[0]) {
    return {
      table: walletTable,
      row: null,
      main: 0,
      profit: 0
    };
  }

  const row =
    rows[0];

  const main =
    numberValue(
      row.main_balance ??
      row.main_wallet ??
      row.balance ??
      row.available_balance,
      0
    );

  const profit =
    numberValue(
      row.profit_balance ??
      row.profit_wallet ??
      row.profit,
      0
    );

  return {
    table: walletTable,
    row,
    main,
    profit
  };
}

async function walletColumn(
  table,
  candidates
) {
  for (const name of candidates) {
    if (
      await columnExists(
        table,
        name
      )
    ) {
      return name;
    }
  }

  return null;
}

async function ensureWallet(userId) {
  let wallet =
    await getWallet(userId);

  if (wallet.row) {
    return wallet;
  }

  const table =
    wallet.table;

  const userColumn =
    await walletColumn(
      table,
      ["user_id"]
    );

  if (!userColumn) {
    throw new Error(
      "Wallet table does not contain user_id."
    );
  }

  const mainColumn =
    await walletColumn(
      table,
      [
        "main_balance",
        "main_wallet",
        "balance",
        "available_balance"
      ]
    );

  const profitColumn =
    await walletColumn(
      table,
      [
        "profit_balance",
        "profit_wallet",
        "profit"
      ]
    );

  if (!mainColumn) {
    throw new Error(
      "Wallet table does not contain a Main Wallet balance column."
    );
  }

  if (profitColumn) {
    await sql.unsafe(
      `
      INSERT INTO "${table}"
        (id, "${userColumn}", "${mainColumn}", "${profitColumn}")
      VALUES
        ($1, $2, 0, 0)
      `,
      [
        crypto.randomUUID(),
        userId
      ]
    );
  } else {
    await sql.unsafe(
      `
      INSERT INTO "${table}"
        (id, "${userColumn}", "${mainColumn}")
      VALUES
        ($1, $2, 0)
      `,
      [
        crypto.randomUUID(),
        userId
      ]
    );
  }

  return getWallet(userId);
}

async function updateWalletBalances(
  userId,
  mainBalance,
  profitBalance
) {
  const wallet =
    await ensureWallet(userId);

  const table =
    wallet.table;

  const mainColumn =
    await walletColumn(
      table,
      [
        "main_balance",
        "main_wallet",
        "balance",
        "available_balance"
      ]
    );

  const profitColumn =
    await walletColumn(
      table,
      [
        "profit_balance",
        "profit_wallet",
        "profit"
      ]
    );

  if (!mainColumn) {
    throw new Error(
      "Main Wallet balance column not found."
    );
  }

  if (profitColumn) {
    await sql.unsafe(
      `
      UPDATE "${table}"
      SET
        "${mainColumn}" = $1,
        "${profitColumn}" = $2
      WHERE user_id = $3
      `,
      [
        mainBalance,
        profitBalance,
        userId
      ]
    );
  } else {
    await sql.unsafe(
      `
      UPDATE "${table}"
      SET "${mainColumn}" = $1
      WHERE user_id = $2
      `,
      [
        mainBalance,
        userId
      ]
    );
  }

  return getWallet(userId);
}

/* =====================================================
   TRANSACTION HELPERS
===================================================== */

async function recordTransaction({
  userId,
  type,
  amount,
  status = "completed",
  description = "",
  reference = null
}) {
  if (
    !(await tableExists(
      "transactions"
    ))
  ) {
    return null;
  }

  const columns = {
    id: await columnExists("transactions", "id"),
    user_id: await columnExists("transactions", "user_id"),
    type: await columnExists("transactions", "type"),
    amount: await columnExists("transactions", "amount"),
    status: await columnExists("transactions", "status"),
    description: await columnExists("transactions", "description"),
    reference: await columnExists("transactions", "reference"),
    created_at: await columnExists("transactions", "created_at")
  };

  const names = [];
  const values = [];
  const placeholders = [];

  const add = (column, value) => {
    if (!columns[column]) return;

    names.push(`"${column}"`);
    values.push(value);
    placeholders.push(`$${values.length}`);
  };

  add("id", crypto.randomUUID());
  add("user_id", userId);
  add("type", type);
  add("amount", amount);
  add("status", status);
  add("description", description);
  add("reference", reference);
  add("created_at", new Date());

  if (!names.length) {
    return null;
  }

  const query = `
    INSERT INTO transactions
      (${names.join(", ")})
    VALUES
      (${placeholders.join(", ")})
    RETURNING *
  `;

  const rows =
    await sql.unsafe(
      query,
      values
    );

  return rows[0] || null;
}

/* =====================================================
   WALLET RESPONSE
===================================================== */

async function customerWallet(
  request
) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const wallet =
    await ensureWallet(
      auth.user.id
    );

  return ok({
    main_balance:
      wallet.main,
    profit_balance:
      wallet.profit,
    total_balance:
      wallet.main +
      wallet.profit
  });
}

/* =====================================================
   KYC
===================================================== */

async function customerKyc(
  request,
  body
) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  await ensureKycSchema();

  const user =
    await findUserById(
      auth.user.id
    );

  if (!user) {
    return bad(
      404,
      "Customer account not found."
    );
  }

  const documentType =
    String(
      body.document_type ||
      body.documentType ||
      ""
    ).trim();

  const documentNumber =
    String(
      body.document_number ||
      body.documentNumber ||
      ""
    ).trim();

  const country =
    String(
      body.country || ""
    ).trim();

  const fullName =
    String(
      body.full_name ||
      body.fullName ||
      `${user.first_name || ""} ${user.last_name || ""}`
    ).trim();

  const notes =
    String(
      body.notes ||
      body.additional_information ||
      body.additionalInfo ||
      ""
    ).trim();

  if (
    !documentType ||
    !documentNumber
  ) {
    return bad(
      400,
      "Document type and document number are required."
    );
  }

  const existing =
    await sql`
      SELECT *
      FROM kyc_submissions
      WHERE user_id = ${user.id}
      ORDER BY created_at DESC
      LIMIT 1
    `;

  if (
    existing[0] &&
    String(
      existing[0].status || ""
    ).toLowerCase() === "approved"
  ) {
    return ok({
      kyc_status: "approved",
      message:
        "Your KYC is already approved."
    });
  }

  if (existing[0]) {
    await sql`
      UPDATE kyc_submissions
      SET
        status = 'pending',
        document_type = ${documentType},
        document_number = ${documentNumber},
        country = ${country || null},
        full_name = ${fullName || null},
        notes = ${notes || null},
        reviewed_by = NULL,
        reviewed_at = NULL,
        updated_at = NOW()
      WHERE id = ${existing[0].id}
    `;
  } else {
    await sql`
      INSERT INTO kyc_submissions (
        id,
        user_id,
        status,
        document_type,
        document_number,
        country,
        full_name,
        notes,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${user.id},
        'pending',
        ${documentType},
        ${documentNumber},
        ${country || null},
        ${fullName || null},
        ${notes || null},
        NOW(),
        NOW()
      )
    `;
  }

  if (
    await columnExists(
      "profiles",
      "kyc_status"
    )
  ) {
    await sql`
      UPDATE profiles
      SET kyc_status = 'pending'
      WHERE id = ${user.id}
    `;
  }

  return ok({
    kyc_status: "pending",
    message:
      "KYC application submitted successfully."
  });
}

async function customerKycStatus(
  request
) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  await ensureKycSchema();

  const user =
    await findUserById(
      auth.user.id
    );

  const rows =
    await sql`
      SELECT *
      FROM kyc_submissions
      WHERE user_id = ${auth.user.id}
      ORDER BY created_at DESC
      LIMIT 1
    `;

  return ok({
    kyc_status:
      user?.kyc_status ||
      rows[0]?.status ||
      "pending",
    kyc:
      rows[0] || null
  });
}

/* =====================================================
   PROFILE
===================================================== */

async function customerProfile(
  request,
  body = null
) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  if (
    request.method === "GET"
  ) {
    const user =
      await findUserById(
        auth.user.id
      );

    return ok({
      profile: user
    });
  }

  const updates = {};
  const allowed = [
    "first_name",
    "last_name",
    "phone",
    "country",
    "address"
  ];

  for (const key of allowed) {
    if (
      body &&
      body[key] !== undefined
    ) {
      updates[key] =
        String(body[key]).trim();
    }
  }

  const entries =
    Object.entries(updates);

  if (!entries.length) {
    return ok({
      profile:
        await findUserById(
          auth.user.id
        )
    });
  }

  const sets = [];
  const values = [];

  for (
    let i = 0;
    i < entries.length;
    i++
  ) {
    const [
      key,
      value
    ] = entries[i];

    sets.push(
      `"${key}" = $${i + 1}`
    );

    values.push(value);
  }

  values.push(
    auth.user.id
  );

  await sql.unsafe(
    `
    UPDATE profiles
    SET ${sets.join(", ")}
    WHERE id = $${values.length}
    `,
    values
  );

  return ok({
    profile:
      await findUserById(
        auth.user.id
      )
  });
}

/* =====================================================
   DEPOSITS
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
      auth.error
    );
  }

  const amount =
    numberValue(
      body.amount,
      0
    );

  const method =
    String(
      body.payment_method ||
      body.paymentMethod ||
      body.method ||
      "bank_transfer"
    )
      .trim()
      .toLowerCase();

  const reference =
    String(
      body.payment_reference ||
      body.paymentReference ||
      body.reference ||
      ""
    ).trim();

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid deposit amount."
    );
  }

  if (
    ![
      "bank_transfer",
      "bank",
      "wallet"
    ].includes(method)
  ) {
    return bad(
      400,
      "Unsupported payment method."
    );
  }

  /*
    A bank-transfer deposit is a REQUEST.
    It must not create wallet money until
    the deposit is confirmed.
  */

  const depositTable =
    await firstExistingTable([
      "deposit_requests",
      "deposits",
      "deposit_requests"
    ]);

  if (!depositTable) {
    return bad(
      500,
      "Deposit table not found."
    );
  }

  const id =
    crypto.randomUUID();

  const columnMap = {
    id: await columnExists(depositTable, "id"),
    user_id: await columnExists(depositTable, "user_id"),
    amount: await columnExists(depositTable, "amount"),
    payment_method: await columnExists(depositTable, "payment_method"),
    method: await columnExists(depositTable, "method"),
    payment_reference: await columnExists(depositTable, "payment_reference"),
    reference: await columnExists(depositTable, "reference"),
    status: await columnExists(depositTable, "status"),
    created_at: await columnExists(depositTable, "created_at"),
    updated_at: await columnExists(depositTable, "updated_at")
  };

  const names = [];
  const values = [];
  const placeholders = [];

  const add = (column, value) => {
    if (!columnMap[column]) return;

    names.push(`"${column}"`);
    values.push(value);
    placeholders.push(
      `$${values.length}`
    );
  };

  add("id", id);
  add("user_id", auth.user.id);
  add("amount", amount);

  if (columnMap.payment_method) {
    add(
      "payment_method",
      method
    );
  } else if (columnMap.method) {
    add(
      "method",
      method
    );
  }

  if (columnMap.payment_reference) {
    add(
      "payment_reference",
      reference || null
    );
  } else if (columnMap.reference) {
    add(
      "reference",
      reference || null
    );
  }

  add("status", "pending");
  add("created_at", new Date());
  add("updated_at", new Date());

  try {
    const rows =
      await sql.unsafe(
        `
        INSERT INTO "${depositTable}"
          (${names.join(", ")})
        VALUES
          (${placeholders.join(", ")})
        RETURNING *
        `,
        values
      );

    await recordTransaction({
      userId: auth.user.id,
      type: "deposit",
      amount,
      status: "pending",
      description:
        `${method} deposit request`,
      reference:
        reference || id
    });

    return ok({
      deposit:
        rows[0] || null,
      message:
        "Deposit request submitted. Your Main Wallet will be credited after the payment is confirmed."
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Deposit request could not be submitted."
    );
  }
}

/* =====================================================
   SEND MONEY
===================================================== */

async function customerTransfer(
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

  const amount =
    numberValue(
      body.amount,
      0
    );

  const recipientValue =
    String(
      body.recipient_username ||
      body.recipientUsername ||
      body.username ||
      body.recipient_email ||
      body.recipientEmail ||
      body.email ||
      ""
    ).trim();

  if (
    !recipientValue
  ) {
    return bad(
      400,
      "Recipient username or email is required."
    );
  }

  if (
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid transfer amount."
    );
  }

  const senderId =
    auth.user.id;

  let recipient =
    await findUserByUsername(
      recipientValue
    );

  if (!recipient) {
    recipient =
      await findUserByEmail(
        recipientValue
      );
  }

  if (!recipient) {
    return bad(
      404,
      "Recipient account not found."
    );
  }

  if (
    recipient.id === senderId
  ) {
    return bad(
      400,
      "You cannot send money to yourself."
    );
  }

  const senderWallet =
    await ensureWallet(
      senderId
    );

  if (
    senderWallet.main <
    amount
  ) {
    return bad(
      400,
      "Insufficient Main Wallet balance."
    );
  }

  const recipientWallet =
    await ensureWallet(
      recipient.id
    );

  const newSenderMain =
    senderWallet.main -
    amount;

  const newRecipientMain =
    recipientWallet.main +
    amount;

  await updateWalletBalances(
    senderId,
    newSenderMain,
    senderWallet.profit
  );

  await updateWalletBalances(
    recipient.id,
    newRecipientMain,
    recipientWallet.profit
  );

  const reference =
    crypto.randomUUID();

  await recordTransaction({
    userId: senderId,
    type: "send",
    amount: -amount,
    status: "completed",
    description:
      `Transfer to ${recipient.username || recipient.email}`,
    reference
  });

  await recordTransaction({
    userId: recipient.id,
    type: "receive",
    amount,
    status: "completed",
    description:
      `Transfer from ${auth.user.username || auth.user.email}`,
    reference
  });

  return ok({
    amount,
    recipient: {
      id: recipient.id,
      username:
        recipient.username,
      email:
        recipient.email
    },
    wallet: {
      main_balance:
        newSenderMain,
      profit_balance:
        senderWallet.profit,
      total_balance:
        newSenderMain +
        senderWallet.profit
    },
    message:
      "Money sent successfully."
  });
}

/* =====================================================
   WITHDRAWAL ACCOUNT
===================================================== */

async function saveWithdrawalAccount(
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
      body.swiftCode ||
      body.other_code ||
      ""
    ).trim();

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

  const table =
    await firstExistingTable([
      "withdrawal_accounts",
      "withdrawal_account",
      "bank_accounts"
    ]);

  if (!table) {
    return bad(
      500,
      "Withdrawal account table not found."
    );
  }

  const existing =
    await sql.unsafe(
      `
      SELECT *
      FROM "${table}"
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 1
      `,
      [auth.user.id]
    ).catch(() => []);

  const id =
    existing[0]?.id ||
    crypto.randomUUID();

  const updates = [];

  if (
    await columnExists(
      table,
      "account_name"
    )
  ) {
    updates.push([
      "account_name",
      accountName
    ]);
  }

  if (
    await columnExists(
      table,
      "account_number"
    )
  ) {
    updates.push([
      "account_number",
      accountNumber
    ]);
  }

  if (
    await columnExists(
      table,
      "bank_name"
    )
  ) {
    updates.push([
      "bank_name",
      bankName
    ]);
  }

  if (
    await columnExists(
      table,
      "swift_code"
    )
  ) {
    updates.push([
      "swift_code",
      swiftCode || null
    ]);
  } else if (
    await columnExists(
      table,
      "other_code"
    )
  ) {
    updates.push([
      "other_code",
      swiftCode || null
    ]);
  }

  if (existing[0]) {
    const sets = [];
    const values = [];

    for (
      let i = 0;
      i < updates.length;
      i++
    ) {
      sets.push(
        `"${updates[i][0]}" = $${i + 1}`
      );
      values.push(
        updates[i][1]
      );
    }

    if (
      await columnExists(
        table,
        "updated_at"
      )
    ) {
      sets.push(
        `"updated_at" = NOW()`
      );
    }

    values.push(
      auth.user.id
    );

    await sql.unsafe(
      `
      UPDATE "${table}"
      SET ${sets.join(", ")}
      WHERE user_id = $${values.length}
      `,
      values
    );
  } else {
    const names = [];
    const values = [];
    const placeholders = [];

    const add = (
      name,
      value
    ) => {
      names.push(`"${name}"`);
      values.push(value);
      placeholders.push(
        `$${values.length}`
      );
    };

    if (
      await columnExists(
        table,
        "id"
      )
    ) {
      add(
        "id",
        id
      );
    }

    if (
      await columnExists(
        table,
        "user_id"
      )
    ) {
      add(
        "user_id",
        auth.user.id
      );
    }

    for (
      const [
        name,
        value
      ] of updates
    ) {
      add(name, value);
    }

    if (
      await columnExists(
        table,
        "created_at"
      )
    ) {
      add(
        "created_at",
        new Date()
      );
    }

    await sql.unsafe(
      `
      INSERT INTO "${table}"
        (${names.join(", ")})
      VALUES
        (${placeholders.join(", ")})
      `,
      values
    );
  }

  return ok({
    withdrawal_account: {
      account_name: accountName,
      account_number:
        accountNumber,
      bank_name: bankName,
      swift_code:
        swiftCode || null
    },
    message:
      "Withdrawal account saved successfully."
  });
}

/* =====================================================
   WITHDRAWAL
===================================================== */

async function customerWithdraw(
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

  const amount =
    numberValue(
      body.amount,
      0
    );

  const walletType =
    String(
      body.wallet_type ||
      body.walletType ||
      body.source ||
      "profit"
    )
      .trim()
      .toLowerCase();

  if (
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid withdrawal amount."
    );
  }

  if (
    ![
      "main",
      "main_wallet",
      "profit",
      "profit_wallet"
    ].includes(walletType)
  ) {
    return bad(
      400,
      "Invalid wallet type."
    );
  }

  const wallet =
    await ensureWallet(
      auth.user.id
    );

  const isProfit =
    walletType === "profit" ||
    walletType === "profit_wallet";

  const sourceBalance =
    isProfit
      ? wallet.profit
      : wallet.main;

  if (
    sourceBalance <
    amount
  ) {
    return bad(
      400,
      isProfit
        ? "Insufficient Profit Wallet balance."
        : "Insufficient Main Wallet balance."
    );
  }

  const withdrawalTable =
    await firstExistingTable([
      "withdrawal_requests",
      "withdrawals"
    ]);

  if (!withdrawalTable) {
    return bad(
      500,
      "Withdrawal table not found."
    );
  }

  const withdrawalId =
    crypto.randomUUID();

  const newMain =
    isProfit
      ? wallet.main
      : wallet.main - amount;

  const newProfit =
    isProfit
      ? wallet.profit - amount
      : wallet.profit;

  /*
    Deduct first from the same real wallet
    that Dashboard / Wallet / Investment read.
  */

  await updateWalletBalances(
    auth.user.id,
    newMain,
    newProfit
  );

  const reference =
    crypto.randomUUID();

  const names = [];
  const values = [];
  const placeholders = [];

  const columns = {
    id: await columnExists(withdrawalTable, "id"),
    user_id: await columnExists(withdrawalTable, "user_id"),
    amount: await columnExists(withdrawalTable, "amount"),
    wallet_type: await columnExists(withdrawalTable, "wallet_type"),
    source_wallet: await columnExists(withdrawalTable, "source_wallet"),
    status: await columnExists(withdrawalTable, "status"),
    reference: await columnExists(withdrawalTable, "reference"),
    created_at: await columnExists(withdrawalTable, "created_at"),
    updated_at: await columnExists(withdrawalTable, "updated_at")
  };

  const add = (
    column,
    value
  ) => {
    if (!columns[column]) {
      return;
    }

    names.push(`"${column}"`);
    values.push(value);
    placeholders.push(
      `$${values.length}`
    );
  };

  add(
    "id",
    withdrawalId
  );

  add(
    "user_id",
    auth.user.id
  );

  add(
    "amount",
    amount
  );

  if (
    columns.wallet_type
  ) {
    add(
      "wallet_type",
      isProfit
        ? "profit"
        : "main"
    );
  } else if (
    columns.source_wallet
  ) {
    add(
      "source_wallet",
      isProfit
        ? "profit"
        : "main"
    );
  }

  add(
    "status",
    "pending"
  );

  add(
    "reference",
    reference
  );

  add(
    "created_at",
    new Date()
  );

  add(
    "updated_at",
    new Date()
  );

  try {
    const rows =
      await sql.unsafe(
        `
        INSERT INTO "${withdrawalTable}"
          (${names.join(", ")})
        VALUES
          (${placeholders.join(", ")})
        RETURNING *
        `,
        values
      );

    await recordTransaction({
      userId:
        auth.user.id,
      type:
        isProfit
          ? "profit_withdrawal"
          : "withdrawal",
      amount:
        -amount,
      status:
        "pending",
      description:
        isProfit
          ? "Profit Wallet withdrawal"
          : "Main Wallet withdrawal",
      reference
    });

    return ok({
      withdrawal:
        rows[0] || null,
      wallet: {
        main_balance:
          newMain,
        profit_balance:
          newProfit,
        total_balance:
          newMain +
          newProfit
      },
      message:
        "Withdrawal request submitted successfully."
    });
  } catch (error) {
    /*
      If the withdrawal request itself fails,
      restore the exact wallet balance.
    */

    await updateWalletBalances(
      auth.user.id,
      wallet.main,
      wallet.profit
    );

    return bad(
      500,
      error?.message ||
        "Unable to submit withdrawal request."
    );
  }
}

/* =====================================================
   INVESTMENT HELPERS
===================================================== */

const INVESTMENT_PLANS = {
  starter: {
    name: "Starter",
    min: 100,
    max: 999,
    profitRate: 0.15
  },

  growth: {
    name: "Growth",
    min: 1000,
    max: 4999,
    profitRate: 0.25
  },

  silver: {
    name: "Silver",
    min: 5000,
    max: 9999,
    profitRate: 0.35
  },

  gold: {
    name: "Gold",
    min: 10000,
    max: 24999,
    profitRate: 0.45
  },

  platinum: {
    name: "Platinum",
    min: 25000,
    max: Number.MAX_SAFE_INTEGER,
    profitRate: 0.50
  }
};

async function ensureInvestmentSchema() {
  if (
    !(await tableExists(
      "investments"
    ))
  ) {
    await sql`
      CREATE TABLE IF NOT EXISTS investments (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL,
        plan TEXT NOT NULL,
        amount NUMERIC NOT NULL,
        profit_rate NUMERIC NOT NULL DEFAULT 0,
        expected_profit NUMERIC NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'active',
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        maturity_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;
  }

  await sql`
    ALTER TABLE investments
    ADD COLUMN IF NOT EXISTS profit_rate NUMERIC
  `;

  await sql`
    ALTER TABLE investments
    ADD COLUMN IF NOT EXISTS expected_profit NUMERIC
  `;

  await sql`
    ALTER TABLE investments
    ADD COLUMN IF NOT EXISTS status TEXT
  `;

  await sql`
    ALTER TABLE investments
    ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ
  `;

  await sql`
    ALTER TABLE investments
    ADD COLUMN IF NOT EXISTS maturity_at TIMESTAMPTZ
  `;

  await sql`
    ALTER TABLE investments
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ
  `;
}

async function customerInvestments(
  request,
  url
) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  await ensureInvestmentSchema();

  const rows =
    await sql`
      SELECT *
      FROM investments
      WHERE user_id = ${auth.user.id}
      ORDER BY created_at DESC
    `;

  const wallet =
    await ensureWallet(
      auth.user.id
    );

  return ok({
    investments:
      rows,
    main_balance:
      wallet.main,
    profit_balance:
      wallet.profit,
    profit_wallet:
      wallet.profit,
    total_balance:
      wallet.main +
      wallet.profit
  });
}

async function customerCreateInvestment(
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

  await ensureInvestmentSchema();

  const amount =
    numberValue(
      body.amount,
      0
    );

  const rawPlan =
    String(
      body.plan ||
      body.package ||
      body.plan_name ||
      body.planName ||
      ""
    )
      .trim()
      .toLowerCase();

  if (
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid investment amount."
    );
  }

  let plan =
    INVESTMENT_PLANS[
      rawPlan
    ];

  if (!plan) {
    for (
      const candidate
      of Object.values(
        INVESTMENT_PLANS
      )
    ) {
      if (
        amount >= candidate.min &&
        amount <= candidate.max
      ) {
        plan = candidate;
        break;
      }
    }
  }

  if (!plan) {
    return bad(
      400,
      "No investment package matches this amount."
    );
  }

  if (
    amount < plan.min ||
    amount > plan.max
  ) {
    return bad(
      400,
      `Investment amount must be between ${plan.min} and ${plan.max}.`
    );
  }

  const wallet =
    await ensureWallet(
      auth.user.id
    );

  /*
    Core rule:
    investment capital comes from Main Wallet.
    Never use Profit Wallet.
  */

  if (
    wallet.main <
    amount
  ) {
    return bad(
      400,
      "Insufficient Main Wallet balance."
    );
  }

  const investmentId =
    crypto.randomUUID();

  const profit =
    amount *
    plan.profitRate;

  /*
    30-day maturity is used as the
    investment maturity point.
  */

  const startedAt =
    new Date();

  const maturityAt =
    new Date(
      startedAt.getTime() +
      30 * 24 * 60 * 60 * 1000
    );

  const newMain =
    wallet.main -
    amount;

  /*
    Investment creation and wallet debit
    happen before returning success.
  */

  await updateWalletBalances(
    auth.user.id,
    newMain,
    wallet.profit
  );

  try {
    const rows =
      await sql`
        INSERT INTO investments (
          id,
          user_id,
          plan,
          amount,
          profit_rate,
          expected_profit,
          status,
          started_at,
          maturity_at,
          created_at,
          updated_at
        )
        VALUES (
          ${investmentId},
          ${auth.user.id},
          ${plan.name},
          ${amount},
          ${plan.profitRate},
          ${profit},
          'active',
          ${startedAt},
          ${maturityAt},
          NOW(),
          NOW()
        )
        RETURNING *
      `;

    await recordTransaction({
      userId:
        auth.user.id,
      type:
        "investment",
      amount:
        -amount,
      status:
        "completed",
      description:
        `Investment in ${plan.name}`,
      reference:
        investmentId
    });

    const updatedWallet =
      await getWallet(
        auth.user.id
      );

    return ok({
      investment:
        rows[0],
      wallet: {
        main_balance:
          updatedWallet.main,
        profit_balance:
          updatedWallet.profit,
        total_balance:
          updatedWallet.main +
          updatedWallet.profit
      },
      message:
        "Investment created successfully."
    });
  } catch (error) {
    /*
      Never leave the customer's money deducted
      if investment creation fails.
    */

    await updateWalletBalances(
      auth.user.id,
      wallet.main,
      wallet.profit
    );

    return bad(
      500,
      error?.message ||
        "Investment could not be created."
    );
  }
}

/* =====================================================
   CUSTOMER CHAT
===================================================== */

async function customerChat(
  request,
  body = null
) {
  const auth =
    await requireUser(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  await ensureChatSchema();

  if (
    request.method === "GET"
  ) {
    const rows =
      await sql`
        SELECT *
        FROM support_messages
        WHERE user_id = ${auth.user.id}
        ORDER BY created_at ASC
      `;

    return ok({
      messages:
        rows
    });
  }

  const message =
    String(
      body?.message || ""
    ).trim();

  const imageUrl =
    String(
      body?.image_url ||
      body?.imageUrl ||
      ""
    ).trim();

  if (
    !message &&
    !imageUrl
  ) {
    return bad(
      400,
      "Message cannot be empty."
    );
  }

  const row =
    await sql`
      INSERT INTO support_messages (
        id,
        user_id,
        sender_role,
        message,
        image_url,
        created_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${auth.user.id},
        'customer',
        ${message || null},
        ${imageUrl || null},
        NOW()
      )
      RETURNING *
    `;

  return ok({
    message:
      row[0],
    data:
      row[0]
  });
}

/* =====================================================
   ADMIN CHAT
===================================================== */

async function adminChat(
  request,
  body = null,
  userId = null
) {
  const auth =
    await requireAdmin(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  await ensureChatSchema();

  if (
    request.method === "GET"
  ) {
    if (userId) {
      const rows =
        await sql`
          SELECT
            sm.*,
            p.username,
            p.email,
            p.first_name,
            p.last_name
          FROM support_messages sm
          LEFT JOIN profiles p
            ON p.id = sm.user_id
          WHERE sm.user_id = ${userId}
          ORDER BY
            sm.created_at ASC
        `;

      return ok({
        messages:
          rows
      });
    }

    const rows =
      await sql`
        SELECT
          sm.user_id,
          MAX(sm.created_at)
            AS last_message_at,
          COUNT(*) AS message_count,
          p.username,
          p.email,
          p.first_name,
          p.last_name
        FROM support_messages sm
        LEFT JOIN profiles p
          ON p.id = sm.user_id
        GROUP BY
          sm.user_id,
          p.username,
          p.email,
          p.first_name,
          p.last_name
        ORDER BY
          last_message_at DESC
      `;

    return ok({
      conversations:
        rows
    });
  }

  if (!userId) {
    return bad(
      400,
      "Customer ID is required."
    );
  }

  const message =
    String(
      body?.message || ""
    ).trim();

  const imageUrl =
    String(
      body?.image_url ||
      body?.imageUrl ||
      ""
    ).trim();

  if (
    !message &&
    !imageUrl
  ) {
    return bad(
      400,
      "Message cannot be empty."
    );
  }

  const row =
    await sql`
      INSERT INTO support_messages (
        id,
        user_id,
        sender_role,
        message,
        image_url,
        created_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${userId},
        'admin',
        ${message || null},
        ${imageUrl || null},
        NOW()
      )
      RETURNING *
    `;

  return ok({
    message:
      row[0],
    data:
      row[0]
  });
}

/* =====================================================
   ADMIN DASHBOARD
===================================================== */

async function adminDashboard() {
  const customers =
    await sql`
      SELECT COUNT(*)::int AS count
      FROM profiles
    `;

  let investments = 0;
  let pendingRequests = 0;

  if (
    await tableExists(
      "investments"
    )
  ) {
    const rows =
      await sql`
        SELECT COUNT(*)::int AS count
        FROM investments
        WHERE status = 'active'
      `;

    investments =
      Number(
        rows[0]?.count || 0
      );
  }

  const requestTables = [
    "deposit_requests",
    "withdrawal_requests",
    "transfer_requests"
  ];

  for (
    const table
    of requestTables
  ) {
    if (
      await tableExists(table)
    ) {
      try {
        const rows =
          await sql.unsafe(
            `
            SELECT COUNT(*)::int AS count
            FROM "${table}"
            WHERE LOWER(COALESCE(status,'')) = 'pending'
            `,
            []
          );

        pendingRequests +=
          Number(
            rows[0]?.count || 0
          );
      } catch {}
    }
  }

  return ok({
    customers:
      Number(
        customers[0]?.count || 0
      ),
    investments,
    pending_requests:
      pendingRequests
  });
}

/* =====================================================
   ADMIN CUSTOMERS
===================================================== */

async function adminCustomers(
  url
) {
  const limit =
    cleanLimit(
      url.searchParams.get(
        "limit"
      ),
      100
    );

  const rows =
    await sql`
      SELECT *
      FROM profiles
      ORDER BY created_at DESC
      LIMIT ${limit}
    `;

  return ok({
    customers:
      rows
  });
}

async function adminCustomer(
  id
) {
  const user =
    await findUserById(
      id
    );

  if (!user) {
    return bad(
      404,
      "Customer not found."
    );
  }

  const wallet =
    await ensureWallet(
      id
    );

  return ok({
    customer:
      user,
    wallet: {
      main_balance:
        wallet.main,
      profit_balance:
        wallet.profit,
      total_balance:
        wallet.main +
        wallet.profit
    }
  });
}

async function updateCustomer(
  request,
  id,
  body
) {
  const fields = [
    "first_name",
    "last_name",
    "phone",
    "country",
    "address"
  ];

  const sets = [];
  const values = [];

  for (
    const field
    of fields
  ) {
    if (
      body[field] !== undefined
    ) {
      sets.push(
        `"${field}" = $${values.length + 1}`
      );

      values.push(
        body[field]
      );
    }
  }

  if (!sets.length) {
    return ok({
      customer:
        await findUserById(id)
    });
  }

  values.push(id);

  await sql.unsafe(
    `
    UPDATE profiles
    SET ${sets.join(", ")}
    WHERE id = $${values.length}
    `,
    values
  );

  return ok({
    customer:
      await findUserById(id)
  });
}

/* =====================================================
   ADMIN WALLETS
===================================================== */

async function adminWallets(
  url
) {
  const limit =
    cleanLimit(
      url.searchParams.get(
        "limit"
      ),
      100
    );

  const walletTable =
    await firstExistingTable([
      "wallets",
      "customer_wallets",
      "user_wallets"
    ]);

  if (!walletTable) {
    return bad(
      500,
      "Wallet table not found."
    );
  }

  const rows =
    await sql.unsafe(
      `
      SELECT
        w.*,
        p.username,
        p.email,
        p.first_name,
        p.last_name
      FROM "${walletTable}" w
      LEFT JOIN profiles p
        ON p.id = w.user_id
      ORDER BY
        w.created_at DESC NULLS LAST
      LIMIT $1
      `,
      [limit]
    );

  return ok({
    wallets:
      rows
  });
}

async function adminWallet(
  userId
) {
  const wallet =
    await ensureWallet(
      userId
    );

  return ok({
    wallet: {
      user_id:
        userId,
      main_balance:
        wallet.main,
      profit_balance:
        wallet.profit,
      total_balance:
        wallet.main +
        wallet.profit
    }
  });
}

async function adjustWallet(
  request,
  body
) {
  const auth =
    await requireAdmin(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const userId =
    String(
      body.user_id ||
      body.userId ||
      ""
    ).trim();

  const amount =
    numberValue(
      body.amount,
      0
    );

  const walletType =
    String(
      body.wallet_type ||
      body.walletType ||
      "main"
    )
      .trim()
      .toLowerCase();

  const action =
    String(
      body.action ||
      "credit"
    )
      .trim()
      .toLowerCase();

  if (!userId) {
    return bad(
      400,
      "User ID is required."
    );
  }

  if (
    amount <= 0
  ) {
    return bad(
      400,
      "Amount must be greater than zero."
    );
  }

  const wallet =
    await ensureWallet(
      userId
    );

  const isProfit =
    walletType === "profit" ||
    walletType === "profit_wallet";

  let main =
    wallet.main;

  let profit =
    wallet.profit;

  const delta =
    action === "debit"
      ? -amount
      : amount;

  if (isProfit) {
    profit += delta;

    if (profit < 0) {
      return bad(
        400,
        "Insufficient Profit Wallet balance."
      );
    }
  } else {
    main += delta;

    if (main < 0) {
      return bad(
        400,
        "Insufficient Main Wallet balance."
      );
    }
  }

  await updateWalletBalances(
    userId,
    main,
    profit
  );

  await recordTransaction({
    userId,
    type:
      `admin_${action}_${isProfit ? "profit" : "main"}`,
    amount:
      delta,
    status:
      "completed",
    description:
      body.description ||
      `Admin ${action} ${isProfit ? "Profit Wallet" : "Main Wallet"}`,
    reference:
      crypto.randomUUID()
  });

  return ok({
    wallet: {
      user_id:
        userId,
      main_balance:
        main,
      profit_balance:
        profit,
      total_balance:
        main +
        profit
    },
    message:
      "Wallet adjusted successfully."
  });
}

/* =====================================================
   ADMIN KYC
===================================================== */

async function adminKyc(
  url
) {
  await ensureKycSchema();

  const status =
    url.searchParams.get(
      "status"
    );

  let rows;

  if (status) {
    rows =
      await sql`
        SELECT
          k.*,
          p.username,
          p.email,
          p.first_name,
          p.last_name,
          p.kyc_status
        FROM kyc_submissions k
        LEFT JOIN profiles p
          ON p.id = k.user_id
        WHERE LOWER(k.status) =
          LOWER(${status})
        ORDER BY
          k.created_at DESC
      `;
  } else {
    rows =
      await sql`
        SELECT
          k.*,
          p.username,
          p.email,
          p.first_name,
          p.last_name,
          p.kyc_status
        FROM kyc_submissions k
        LEFT JOIN profiles p
          ON p.id = k.user_id
        ORDER BY
          k.created_at DESC
      `;
  }

  return ok({
    kyc:
      rows
  });
}

async function reviewKyc(
  request,
  id,
  body
) {
  const auth =
    await requireAdmin(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  await ensureKycSchema();

  const status =
    String(
      body.status ||
      body.kyc_status ||
      ""
    )
      .trim()
      .toLowerCase();

  if (
    ![
      "approved",
      "rejected",
      "pending"
    ].includes(status)
  ) {
    return bad(
      400,
      "Invalid KYC status."
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM kyc_submissions
      WHERE user_id = ${id}
      ORDER BY created_at DESC
      LIMIT 1
    `;

  if (!rows[0]) {
    return bad(
      404,
      "KYC application not found."
    );
  }

  await sql`
    UPDATE kyc_submissions
    SET
      status = ${status},
      reviewed_by = ${auth.user.id},
      reviewed_at = NOW(),
      updated_at = NOW()
    WHERE id = ${rows[0].id}
  `;

  if (
    await columnExists(
      "profiles",
      "kyc_status"
    )
  ) {
    await sql`
      UPDATE profiles
      SET kyc_status = ${status}
      WHERE id = ${id}
    `;
  }

  return ok({
    kyc_status:
      status,
    message:
      `KYC ${status}.`
  });
}

/* =====================================================
   ADMIN TRANSACTIONS
===================================================== */

async function adminTransactions(
  url
) {
  const limit =
    cleanLimit(
      url.searchParams.get(
        "limit"
      ),
      100
    );

  if (
    !(await tableExists(
      "transactions"
    ))
  ) {
    return ok({
      transactions: []
    });
  }

  const rows =
    await sql`
      SELECT
        t.*,
        p.username,
        p.email,
        p.first_name,
        p.last_name
      FROM transactions t
      LEFT JOIN profiles p
        ON p.id = t.user_id
      ORDER BY
        t.created_at DESC
      LIMIT ${limit}
    `;

  return ok({
    transactions:
      rows
  });
}

/* =====================================================
   ADMIN REQUESTS
===================================================== */

async function adminRequests(
  url
) {
  const result = [];

  const requestTables = [
    "deposit_requests",
    "withdrawal_requests",
    "transfer_requests"
  ];

  const limit =
    cleanLimit(
      url.searchParams.get(
        "limit"
      ),
      100
    );

  for (
    const table
    of requestTables
  ) {
    if (
      !(await tableExists(
        table
      ))
    ) {
      continue;
    }

    try {
      const rows =
        await sql.unsafe(
          `
          SELECT
            r.*,
            p.username,
            p.email,
            p.first_name,
            p.last_name
          FROM "${table}" r
          LEFT JOIN profiles p
            ON p.id = r.user_id
          ORDER BY
            r.created_at DESC
          LIMIT $1
          `,
          [limit]
        );

      result.push(
        ...rows.map(
          row => ({
            ...row,
            request_type:
              table.replace(
                "_requests",
                ""
              )
          })
        )
      );
    } catch {}
  }

  result.sort(
    (a, b) =>
      new Date(
        b.created_at || 0
      ) -
      new Date(
        a.created_at || 0
      )
  );

  return ok({
    requests:
      result.slice(
        0,
        limit
      )
  });
}

/* =====================================================
   AUTH — REGISTER
===================================================== */

async function register(
  request,
  body
) {
  const email =
    normalizeEmail(
      body.email
    );

  const password =
    String(
      body.password || ""
    );

  const firstName =
    String(
      body.first_name ||
      body.firstName ||
      ""
    ).trim();

  const lastName =
    String(
      body.last_name ||
      body.lastName ||
      ""
    ).trim();

  const username =
    String(
      body.username ||
      ""
    )
      .trim()
      .toLowerCase();

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
    password.length <
    6
  ) {
    return bad(
      400,
      "Password must contain at least 6 characters."
    );
  }

  const existing =
    await findUserByEmail(
      email
    );

  if (existing) {
    return bad(
      409,
      "An account with this email already exists."
    );
  }

  if (
    username &&
    await findUserByUsername(
      username
    )
  ) {
    return bad(
      409,
      "That username is already taken."
    );
  }

  const userId =
    crypto.randomUUID();

  const passwordHash =
    hashPassword(
      password
    );

  const columns = [
    "id",
    "email"
  ];

  const values = [
    userId,
    email
  ];

  if (
    await columnExists(
      "profiles",
      "password_hash"
    )
  ) {
    columns.push(
      "password_hash"
    );
    values.push(
      passwordHash
    );
  }

  if (
    await columnExists(
      "profiles",
      "first_name"
    )
  ) {
    columns.push(
      "first_name"
    );
    values.push(
      firstName || null
    );
  }

  if (
    await columnExists(
      "profiles",
      "last_name"
    )
  ) {
    columns.push(
      "last_name"
    );
    values.push(
      lastName || null
    );
  }

  if (
    await columnExists(
      "profiles",
      "username"
    )
  ) {
    columns.push(
      "username"
    );
    values.push(
      username || null
    );
  }

  if (
    await columnExists(
      "profiles",
      "kyc_status"
    )
  ) {
    columns.push(
      "kyc_status"
    );
    values.push(
      "pending"
    );
  }

  if (
    await columnExists(
      "profiles",
      "role"
    )
  ) {
    columns.push(
      "role"
    );
    values.push(
      "customer"
    );
  }

  const placeholders =
    values.map(
      (_, i) =>
        `$${i + 1}`
    );

  try {
    await sql.unsafe(
      `
      INSERT INTO profiles
        (${columns.map(
          c => `"${c}"`
        ).join(", ")})
      VALUES
        (${placeholders.join(", ")})
      `,
      values
    );
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to create account."
    );
  }

  try {
    await ensureWallet(
      userId
    );
  } catch (error) {
    console.warn(
      "Wallet creation warning:",
      error?.message
    );
  }

  try {
    await sendVerificationEmail(
      request,
      {
        id: userId,
        email,
        first_name:
          firstName
      }
    );
  } catch (error) {
    console.warn(
      "Verification email warning:",
      error?.message
    );
  }

  return ok({
    user_id:
      userId,
    message:
      "Account created successfully. Please confirm your email."
  });
}

/* =====================================================
   AUTH — LOGIN
   BACKWARD-COMPATIBLE LOGIN FIX
===================================================== */

async function login(
  request,
  body
) {

  const loginValue =
    String(
      body.email ||
      body.username ||
      body.user_name ||
      body.identifier ||
      ""
    ).trim();

  const password =
    String(
      body.password || ""
    );

  if(
    !loginValue ||
    !password
  ){
    return bad(
      400,
      "Email/username and password are required."
    );
  }

  /*
   * First try email exactly as the original
   * authentication system does.
   */
  let user =
    await findUserByEmail(
      normalizeEmail(
        loginValue
      )
    );

  /*
   * If the customer entered their username,
   * support username login as well.
   */
  if(!user){

    user =
      await findUserByUsername(
        loginValue
      );

  }

  if(!user){

    return bad(
      401,
      "Invalid email or password."
    );

  }

  /*
   * Existing customer passwords are stored on
   * the profiles record in password_hash.
   *
   * Do NOT create a new credential system here.
   * Do NOT require auth_credentials.
   */
  const storedPassword =
    user.password_hash ||
    user.password ||
    "";

  let passwordValid = false;

  /*
   * Current CoinForest scrypt format:
   *
   * salt:hex-derived-key
   */
  if(
    String(
      storedPassword
    ).includes(":")
  ){

    passwordValid =
      verifyPassword(
        password,
        storedPassword
      );

  }

  /*
   * Backward compatibility for older SHA-256
   * password records.
   */
  if(
    !passwordValid &&
    /^[a-f0-9]{64}$/i.test(
      String(
        storedPassword
      )
    )
  ){

    const hash =
      crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");

    passwordValid =
      hash.toLowerCase() ===
      String(
        storedPassword
      ).toLowerCase();

  }

  /*
   * Legacy plaintext compatibility.
   *
   * If an old account still has its password in
   * legacy form, authenticate it and immediately
   * upgrade it to the current secure format.
   */
  if(
    !passwordValid &&
    storedPassword &&
    !String(
      storedPassword
    ).includes(":") &&
    !/^[a-f0-9]{64}$/i.test(
      String(
        storedPassword
      )
    )
  ){

    passwordValid =
      String(
        storedPassword
      ) === password;

  }

  if(!passwordValid){

    return bad(
      401,
      "Invalid email or password."
    );

  }

  /*
   * Upgrade legacy password storage after a
   * successful login.
   */
  if(
    !String(
      storedPassword
    ).includes(":")
  ){

    try{

      if(
        await columnExists(
          "profiles",
          "password_hash"
        )
      ){

        const upgradedHash =
          hashPassword(
            password
          );

        await sql`
          UPDATE profiles
          SET password_hash =
            ${upgradedHash}
          WHERE id =
            ${user.id}
        `;

      }

    }catch(error){

      /*
       * Password authentication already succeeded.
       * A migration failure must NOT prevent login.
       */
      console.warn(
        "Password migration warning:",
        error?.message
      );

    }

  }

  /*
   * Create the normal CoinForest session.
   */
  const rawToken =
    createToken();

  const tokenHash =
    hashToken(
      rawToken
    );

  /*
   * Preserve the existing session architecture.
   */
  if(
    !(await tableExists(
      "auth_sessions"
    ))
  ){

    await sql`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id UUID PRIMARY KEY,
        user_id UUID NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

  }

  await sql`
    INSERT INTO auth_sessions (
      id,
      user_id,
      token_hash,
      expires_at,
      created_at
    )
    VALUES (
      ${crypto.randomUUID()},
      ${user.id},
      ${tokenHash},
      NOW() +
        INTERVAL '30 days',
      NOW()
    )
  `;

  return ok({

    token:
      rawToken,

    user: {

      id:
        user.id,

      email:
        user.email,

      username:
        user.username,

      first_name:
        user.first_name,

      last_name:
        user.last_name,

      role:
        user.role,

      kyc_status:
        user.kyc_status

    }

  });

}

/* =====================================================
   AUTH — VERIFY EMAIL
===================================================== */

async function verifyEmail(
  request,
  token
) {
  if (!token) {
    return bad(
      400,
      "Verification token is required."
    );
  }

  const tokenHash =
    hashToken(
      token
    );

  const rows =
    await sql`
      SELECT *
      FROM auth_email_tokens
      WHERE token_hash = ${tokenHash}
        AND token_type =
          'email_verification'
        AND used_at IS NULL
        AND expires_at > NOW()
      LIMIT 1
    `;

  if (!rows[0]) {
    return bad(
      400,
      "This verification link is invalid or expired."
    );
  }

  await sql`
    UPDATE auth_email_tokens
    SET used_at = NOW()
    WHERE id = ${rows[0].id}
  `;

  if (
    await columnExists(
      "profiles",
      "email_verified"
    )
  ) {
    await sql`
      UPDATE profiles
      SET email_verified = TRUE
      WHERE id = ${rows[0].user_id}
    `;
  }

  return ok({
    message:
      "Email verified successfully."
  });
}

/* =====================================================
   ADMIN ACCOUNT APPROVAL
===================================================== */

async function approveAccount(
  request,
  userId,
  approved
) {
  const auth =
    await requireAdmin(
      request
    );

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const user =
    await findUserById(
      userId
    );

  if (!user) {
    return bad(
      404,
      "Customer not found."
    );
  }

  if (
    await columnExists(
      "profiles",
      "account_status"
    )
  ) {
    await sql`
      UPDATE profiles
      SET account_status =
        ${approved
          ? "active"
          : "declined"}
      WHERE id = ${userId}
    `;
  }

  if (
    approved &&
    await columnExists(
      "profiles",
      "email_verified"
    )
  ) {
    await sql`
      UPDATE profiles
      SET email_verified = TRUE
      WHERE id = ${userId}
    `;
  }

  return ok({
    approved,
    message:
      approved
        ? "Customer account approved."
        : "Customer account declined."
  });
}

/* =====================================================
   ADMIN RESET PASSWORD
===================================================== */

async function resetAdminPassword(
  request,
  body
) {
  const resetKey =
    request.headers.get(
      "X-Admin-Reset-Key"
    );

  const expectedKey =
    process.env.ADMIN_RESET_KEY;

  if (
    !expectedKey ||
    resetKey !== expectedKey
  ) {
    return bad(
      403,
      "Invalid admin reset key."
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
    password.length <
      6
  ) {
    return bad(
      400,
      "Valid email and password are required."
    );
  }

  const user =
    await findUserByEmail(
      email
    );

  if (!user) {
    return bad(
      404,
      "Admin account not found."
    );
  }

  const hash =
    hashPassword(
      password
    );

  if (
    await columnExists(
      "profiles",
      "password_hash"
    )
  ) {
    await sql`
      UPDATE profiles
      SET password_hash =
        ${hash}
      WHERE id = ${user.id}
    `;
  }

  return ok({
    message:
      "Admin password reset successfully."
  });
}

/* =====================================================
   VERCEL RESPONSE ADAPTER
===================================================== */

function writeWebResponse(
  res,
  webResponse
) {
  return webResponse
    .json()
    .then(async data => {
      const text =
        JSON.stringify(
          data
        );

      res.statusCode =
        webResponse.status;

      for (
        const [
          key,
          value
        ]
        of webResponse.headers
      ) {
        res.setHeader(
          key,
          value
        );
      }

      res.end(text);
    });
}

/* =====================================================
   MAIN HANDLER
===================================================== */

export default async function handler(
  req,
  res
) {
  const request =
    new Request(
      `https://${req.headers.host}${req.url}`,
      {
        method:
          req.method,
        headers:
          req.headers,
        body:
          req.method === "GET" ||
          req.method === "HEAD"
            ? undefined
            : JSON.stringify(
                req.body || {}
              )
      }
    );

  const url =
    new URL(
      request.url
    );

  const path =
    url.pathname;

  const method =
    request.method
      .toUpperCase();

  try {
    if (
      method === "OPTIONS"
    ) {
      res.statusCode =
        204;

      for (
        const [
          key,
          value
        ]
        of Object.entries(
          headers
        )
      ) {
        res.setHeader(
          key,
          value
        );
      }

      res.end();

      return;
    }

    /* =================================================
       AUTH
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/auth/register" ||
        path === "/api/register"
      )
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

    if (
      method === "POST" &&
      (
        path === "/api/auth/login" ||
        path === "/api/login"
      )
    ) {
      return writeWebResponse(
        res,
        await login(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    if (
      method === "GET" &&
      (
        path === "/api/auth/verify-email" ||
        path === "/api/verify-email"
      )
    ) {
      return writeWebResponse(
        res,
        await verifyEmail(
          request,
          url.searchParams.get(
            "token"
          )
        )
      );
    }

    /* =================================================
       CUSTOMER WALLET
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/wallet" ||
        path === "/api/user/wallet" ||
        path === "/api/wallet"
      )
    ) {
      return writeWebResponse(
        res,
        await customerWallet(
          request
        )
      );
    }

    /* =================================================
       CUSTOMER KYC
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/kyc" ||
        path === "/api/user/kyc" ||
        path === "/api/kyc"
      )
    ) {
      return writeWebResponse(
        res,
        await customerKycStatus(
          request
        )
      );
    }

    if (
      method === "POST" &&
      (
        path === "/api/customer/kyc" ||
        path === "/api/user/kyc" ||
        path === "/api/kyc"
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
       CUSTOMER PROFILE
    ================================================= */

    if (
      (
        method === "GET" ||
        method === "PUT" ||
        method === "PATCH"
      ) &&
      (
        path === "/api/customer/profile" ||
        path === "/api/user/profile" ||
        path === "/api/profile"
      )
    ) {
      return writeWebResponse(
        res,
        await customerProfile(
          request,
          method === "GET"
            ? null
            : await jsonBody(
                request
              )
        )
      );
    }

    /* =================================================
       CUSTOMER DEPOSITS
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/customer/deposits" ||
        path === "/api/customer/deposit" ||
        path === "/api/user/deposits" ||
        path === "/api/deposit"
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
       CUSTOMER SEND / TRANSFER
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/customer/transfers" ||
        path === "/api/customer/transfer" ||
        path === "/api/user/transfers" ||
        path === "/api/transfer"
      )
    ) {
      return writeWebResponse(
        res,
        await customerTransfer(
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
      (
        method === "POST" ||
        method === "PUT"
      ) &&
      (
        path ===
          "/api/customer/withdrawal-account" ||
        path ===
          "/api/customer/withdrawal-account/save" ||
        path ===
          "/api/user/withdrawal-account"
      )
    ) {
      return writeWebResponse(
        res,
        await saveWithdrawalAccount(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER WITHDRAWAL
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/customer/withdrawals" ||
        path === "/api/customer/withdrawal" ||
        path === "/api/user/withdrawals" ||
        path === "/api/withdrawal"
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

    if (
      method === "POST" &&
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
        await customerCreateInvestment(
          request,
          await jsonBody(
            request
          )
        )
      );
    }

    /* =================================================
       CUSTOMER CHAT
    ================================================= */

    if (
      (
        method === "GET" ||
        method === "POST"
      ) &&
      (
        path === "/api/customer/chat" ||
        path === "/api/user/chat" ||
        path === "/api/chat"
      )
    ) {
      return writeWebResponse(
        res,
        await customerChat(
          request,
          method === "POST"
            ? await jsonBody(
                request
              )
            : null
        )
      );
    }

    /* =================================================
       ADMIN CHAT
    ================================================= */

    if (
      method === "GET" &&
      path ===
        "/api/admin/chat"
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
        await adminChat(
          request,
          null,
          url.searchParams.get(
            "conversation_id"
          )
        )
      );
    }

    if (
      method === "POST" &&
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

      return writeWebResponse(
        res,
        await adminChat(
          request,
          await jsonBody(
            request
          ),
          path.split(
            "/"
          ).pop()
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
       ADMIN ACCOUNT APPROVAL
    ================================================= */

    if (
      method === "POST" &&
      path.startsWith(
        "/api/admin/account/approve/"
      )
    ) {
      return writeWebResponse(
        res,
        await approveAccount(
          request,
          path.split(
            "/"
          ).pop(),
          true
        )
      );
    }

    if (
      method === "POST" &&
      (
        path.startsWith(
          "/api/admin/account/reject/"
        ) ||
        path.startsWith(
          "/api/admin/account/decline/"
        )
      )
    ) {
      return writeWebResponse(
        res,
        await approveAccount(
          request,
          path.split(
            "/"
          ).pop(),
          false
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

      await ensureInvestmentSchema();

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
       ADMIN REQUESTS
    ================================================= */

    if (
      method === "GET" &&
      (
        path ===
          "/api/admin/requests" ||
        path ===
          "/api/admin/requests/all"
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

      return writeWebResponse(
        res,
        await adminTransactions(
          url
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
