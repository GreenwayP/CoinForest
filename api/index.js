/* =====================================================
   COINFOREST API — COMPLETE INDEX.JS
   ADMIN CHAT / TRANSACTIONS / ACTIVITIES FIX
   Existing authentication, KYC, chat, requests,
   investments and customer functions preserved.
===================================================== */

import crypto from "crypto";
import bcrypt from "bcryptjs";
import { neon } from "@neondatabase/serverless";

const sql = neon(process.env.DATABASE_URL);

const jsonHeaders = {
  "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, X-Requested-With",
  "Access-Control-Allow-Methods":
    "GET, POST, PUT, PATCH, DELETE, OPTIONS"
};

function response(status, data) {
  return {
    status,
    headers: jsonHeaders,
    body: JSON.stringify(data)
  };
}

function ok(data = {}) {
  return response(200, {
    success: true,
    ...data
  });
}

function bad(status, error) {
  return response(status, {
    success: false,
    error
  });
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function createToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(String(token))
    .digest("hex");
}

function bearer(request) {
  const header =
    request.headers.get("authorization") ||
    request.headers.get("Authorization") ||
    "";

  if (!header) return null;

  if (
    header.toLowerCase().startsWith("bearer ")
  ) {
    return header.slice(7).trim();
  }

  return header.trim();
}

async function jsonBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function verifyPassword(password, hash) {
  try {
    return await bcrypt.compare(
      String(password || ""),
      String(hash || "")
    );
  } catch {
    return false;
  }
}

async function hashPassword(password) {
  return bcrypt.hash(
    String(password || ""),
    12
  );
}

/* =====================================================
   CORS / RESPONSE
===================================================== */

function writeWebResponse(res, result) {
  const headers = new Headers(
    result?.headers || jsonHeaders
  );

  Object.entries(
    result?.headers || {}
  ).forEach(([key, value]) => {
    headers.set(key, value);
  });

  res.statusCode =
    Number(result?.status || 200);

  for (const [key, value] of headers.entries()) {
    res.setHeader(key, value);
  }

  res.end(
    result?.body ||
      JSON.stringify({
        success: false,
        error: "Empty response."
      })
  );
}

/* =====================================================
   CUSTOMER WALLET HELPERS
===================================================== */

async function ensureUserWallets(userId) {
  const profile =
    await sql`
      SELECT id
      FROM profiles
      WHERE id = ${userId}
      LIMIT 1
    `;

  if (!profile.length) return;

  /*
   * Create the wallet records expected by the
   * customer dashboard if they do not exist.
   */
  const walletTypes = [
    "main",
    "profit",
    "udc"
  ];

  for (const walletType of walletTypes) {
    const existing =
      await sql`
        SELECT id
        FROM wallets
        WHERE user_id = ${userId}
          AND LOWER(
            COALESCE(wallet_type, '')
          ) = ${walletType}
        LIMIT 1
      `;

    if (!existing.length) {
      await sql`
        INSERT INTO wallets (
          id,
          user_id,
          wallet_type,
          balance,
          currency,
          status,
          created_at,
          updated_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${userId},
          ${walletType},
          0,
          'USD',
          'active',
          NOW(),
          NOW()
        )
      `;
    }
  }
}

/* =====================================================
   REGISTER
===================================================== */

async function register(body) {
  const email =
    normalizeEmail(body.email);

  const password =
    String(body.password || "");

  const firstName =
    String(body.first_name || "")
      .trim();

  const lastName =
    String(body.last_name || "")
      .trim();

  const username =
    String(body.username || "")
      .trim();

  if (!email || !password) {
    return bad(
      400,
      "Email and password are required."
    );
  }

  if (password.length < 6) {
    return bad(
      400,
      "Password must be at least 6 characters."
    );
  }

  const existing =
    await sql`
      SELECT id
      FROM profiles
      WHERE LOWER(email) = ${email}
      LIMIT 1
    `;

  if (existing.length) {
    return bad(
      409,
      "An account with this email already exists."
    );
  }

  const passwordHash =
    await hashPassword(password);

  const userId =
    crypto.randomUUID();

  const created =
    await sql`
      INSERT INTO profiles (
        id,
        email,
        first_name,
        last_name,
        username,
        status,
        kyc_status,
        email_verified_at,
        created_at,
        updated_at
      )
      VALUES (
        ${userId},
        ${email},
        ${firstName || null},
        ${lastName || null},
        ${username || null},
        'pending',
        'pending',
        NULL,
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  await sql`
    INSERT INTO auth_credentials (
      id,
      user_id,
      password_hash,
      failed_login_attempts,
      created_at,
      updated_at
    )
    VALUES (
      ${crypto.randomUUID()},
      ${userId},
      ${passwordHash},
      0,
      NOW(),
      NOW()
    )
  `;

  await ensureUserWallets(userId);

  return response(201, {
    success: true,
    message:
      "Account created. Your account is awaiting administrator approval. Email verification is handled by administrator approval for now.",
    user: {
      id: userId,
      email,
      first_name: firstName,
      last_name: lastName,
      username,
      status: "pending",
      kyc_status: "pending",
      email_verified: false
    }
  });
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

  const result =
    await sql`
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
    !(await verifyPassword(
      password,
      user.password_hash
    ))
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

  const token =
    createToken();

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
   * Administrator approval is the temporary
   * email-verification mechanism.
   *
   * Therefore an active/approved account is
   * considered email verified by the API even
   * if email_verified_at was never populated.
   */
  const accountApproved =
    [
      "active",
      "approved"
    ].includes(
      String(
        user.status || ""
      ).toLowerCase()
    );

  return ok({
    message:
      "Login successful.",

    token,

    access_token:
      token,

    session_token:
      token,

    session: {
      access_token:
        token,
      token_type:
        "Bearer",
      expires_in:
        60 * 60 * 24 * 30
    },

    account_approved:
      accountApproved,

    email_verified:
      accountApproved ||
      !!user.email_verified_at,

    kyc_status:
      user.kyc_status ||
      null,

    user: {
      id: user.id,
      email: user.email,
      first_name:
        user.first_name,
      last_name:
        user.last_name,
      username:
        user.username,
      role:
        user.role_name,
      status:
        user.status,
      kyc_status:
        user.kyc_status ||
        null,
      email_verified:
        accountApproved ||
        !!user.email_verified_at
    }
  });
}

/* =====================================================
   AUTHENTICATE SESSION
===================================================== */

async function authenticate(request) {
  const token =
    bearer(request);

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

  const result =
    await sql`
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
        "Session expired or invalid."
    };
  }

  const user =
    result[0];

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
    user
  };
}

/* =====================================================
   CURRENT USER
===================================================== */

async function currentUser(request) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  return ok({
    user: {
      ...auth.user,
      email_verified:
        [
          "active",
          "approved"
        ].includes(
          String(
            auth.user.status || ""
          ).toLowerCase()
        ) ||
        !!auth.user.email_verified_at
    }
  });
}

/* =====================================================
   ADMIN AUTH
===================================================== */

async function requireAdmin(request) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return auth;
  }

  const role =
    String(
      auth.user.role_name ||
      ""
    ).toLowerCase();

  if (
    ![
      "admin",
      "administrator",
      "super_admin",
      "superadmin"
    ].includes(role)
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
   WALLET LIST
===================================================== */

async function getWallets(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const userId =
    auth.user.id;

  await ensureUserWallets(
    userId
  );

  const wallets =
    await sql`
      SELECT
        id,
        user_id,
        wallet_type,
        balance,
        currency,
        status,
        created_at,
        updated_at
      FROM wallets
      WHERE user_id = ${userId}
      ORDER BY
        CASE
          WHEN LOWER(wallet_type) = 'main'
            THEN 1
          WHEN LOWER(wallet_type) = 'udc'
            THEN 2
          WHEN LOWER(wallet_type) = 'profit'
            THEN 3
          ELSE 4
        END,
        created_at ASC
    `;

  return ok({
    wallets
  });
}

/* =====================================================
   WALLET DETAIL
===================================================== */

async function getWallet(
  request,
  id
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const wallet =
    await sql`
      SELECT
        id,
        user_id,
        wallet_type,
        balance,
        currency,
        status,
        created_at,
        updated_at
      FROM wallets
      WHERE id = ${id}
        AND user_id =
          ${auth.user.id}
      LIMIT 1
    `;

  if (!wallet.length) {
    return bad(
      404,
      "Wallet not found."
    );
  }

  return ok({
    wallet:
      wallet[0]
  });
}

/* =====================================================
   TRANSACTIONS
===================================================== */

async function customerTransactions(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const userId =
    auth.user.id;

  const transactions =
    await sql`
      SELECT
        t.*
      FROM transactions t
      WHERE t.user_id =
        ${userId}
      ORDER BY
        t.created_at DESC
      LIMIT 200
    `;

  return ok({
    transactions
  });
}

/* =====================================================
   CUSTOMER PROFILE
===================================================== */

async function customerProfile(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const rows =
    await sql`
      SELECT
        p.*
      FROM profiles p
      WHERE p.id =
        ${auth.user.id}
      LIMIT 1
    `;

  if (!rows.length) {
    return bad(
      404,
      "Customer profile not found."
    );
  }

  return ok({
    profile:
      rows[0]
  });
}

/* =====================================================
   UPDATE CUSTOMER PROFILE
===================================================== */

async function updateCustomerProfile(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const body =
    await jsonBody(request);

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

  const phone =
    body.phone !== undefined
      ? String(
          body.phone
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
        phone =
          COALESCE(
            ${phone},
            phone
          ),
        updated_at =
          NOW()
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
   KYC STATUS
===================================================== */

async function customerKycStatus(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const rows =
    await sql`
      SELECT
        id,
        kyc_status,
        email_verified_at,
        status
      FROM profiles
      WHERE id =
        ${auth.user.id}
      LIMIT 1
    `;

  if (!rows.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  return ok({
    kyc_status:
      rows[0].kyc_status ||
      "pending",

    approved:
      String(
        rows[0].kyc_status ||
        ""
      ).toLowerCase() ===
      "approved",

    account_status:
      rows[0].status,

    email_verified:
      [
        "active",
        "approved"
      ].includes(
        String(
          rows[0].status || ""
        ).toLowerCase()
      ) ||
      !!rows[0].email_verified_at
  });
}

/* =====================================================
   KYC APPLICATION
===================================================== */

async function submitKyc(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const body =
    await jsonBody(request);

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

  const fullName =
    String(
      body.full_name ||
      body.fullName ||
      ""
    ).trim();

  if (
    !documentType ||
    !documentNumber
  ) {
    return bad(
      400,
      "KYC document type and document number are required."
    );
  }

  const existing =
    await sql`
      SELECT id
      FROM kyc_submissions
      WHERE user_id =
        ${auth.user.id}
        AND LOWER(
          COALESCE(status, '')
        ) IN (
          'pending',
          'submitted',
          'approved'
        )
      ORDER BY
        created_at DESC
      LIMIT 1
    `;

  if (existing.length) {
    return bad(
      409,
      "A KYC application already exists for this account."
    );
  }

  const inserted =
    await sql`
      INSERT INTO kyc_submissions (
        id,
        user_id,
        full_name,
        document_type,
        document_number,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${auth.user.id},
        ${fullName || null},
        ${documentType},
        ${documentNumber},
        'pending',
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  await sql`
    UPDATE profiles
    SET
      kyc_status = 'pending',
      updated_at = NOW()
    WHERE id =
      ${auth.user.id}
  `;

  return response(201, {
    success: true,
    message:
      "KYC application submitted successfully.",
    kyc:
      inserted[0]
  });
}

/* =====================================================
   ADMIN CUSTOMER UPDATE
===================================================== */

async function adminUpdateCustomer(
  request,
  id
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

  const body =
    await jsonBody(request);

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

        /*
         * Administrator approval now also acts
         * as the temporary email verification.
         */
        email_verified_at =
          CASE
            WHEN LOWER(
              COALESCE(
                ${status},
                status,
                ''
              )
            ) IN (
              'active',
              'approved'
            )
            THEN COALESCE(
              email_verified_at,
              NOW()
            )
            ELSE email_verified_at
          END,

        kyc_status =
          COALESCE(
            ${kycStatus},
            kyc_status
          ),

        updated_at =
          NOW()

      WHERE id =
        ${id}

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
   ADMIN KYC APPROVAL
===================================================== */

async function adminUpdateKyc(
  request,
  id
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

  const body =
    await jsonBody(request);

  const decision =
    String(
      body.status ||
      body.kyc_status ||
      body.decision ||
      ""
    )
      .trim()
      .toLowerCase();

  if (
    ![
      "approved",
      "declined",
      "rejected",
      "pending"
    ].includes(decision)
  ) {
    return bad(
      400,
      "Invalid KYC decision."
    );
  }

  const finalStatus =
    decision === "rejected"
      ? "declined"
      : decision;

  const updated =
    await sql`
      UPDATE profiles
      SET
        kyc_status =
          ${finalStatus},
        updated_at =
          NOW()
      WHERE id =
        ${id}
      RETURNING *
    `;

  if (!updated.length) {
    return bad(
      404,
      "Customer not found."
    );
  }

  return ok({
    message:
      `KYC ${finalStatus}.`,
    customer:
      updated[0]
  });
}

/* =====================================================
   ADMIN WALLET ADJUSTMENT
===================================================== */

async function adminAdjustWallet(
  request
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const body =
    await jsonBody(request);

  const walletId =
    body.wallet_id ||
    body.walletId;

  const action =
    String(
      body.action || ""
    )
      .trim()
      .toLowerCase();

  const amount =
    Number(
      body.amount
    );

  const description =
    String(
      body.description ||
      "Administrator wallet adjustment"
    ).trim();

  if (!walletId) {
    return bad(
      400,
      "Wallet ID is required."
    );
  }

  if (
    ![
      "credit",
      "debit"
    ].includes(action)
  ) {
    return bad(
      400,
      "Action must be credit or debit."
    );
  }

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "A valid positive amount is required."
    );
  }

  /*
   * Prefer the SECURITY DEFINER RPC so that
   * administrative balance changes follow the
   * database's authorization rules.
   */
  try {
    const rpc =
      await sql`
        SELECT *
        FROM public.admin_adjust_wallet(
          ${walletId}::uuid,
          ${action},
          ${amount},
          ${description}
        )
      `;

    return ok({
      message:
        "Wallet adjusted successfully.",
      result:
        rpc
    });
  } catch (rpcError) {
    /*
     * Do not silently fake a successful balance
     * adjustment when the RPC is unavailable.
     */
    return bad(
      500,
      rpcError?.message ||
        "Wallet adjustment failed."
    );
  }
}

/* =====================================================
   DEPOSIT REQUEST
===================================================== */

async function createDeposit(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const body =
    await jsonBody(request);

  const amount =
    Number(
      body.amount
    );

  const walletId =
    body.wallet_id ||
    body.walletId ||
    null;

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid deposit amount."
    );
  }

  const profile =
    await sql`
      SELECT
        status,
        kyc_status
      FROM profiles
      WHERE id =
        ${auth.user.id}
      LIMIT 1
    `;

  if (
    !profile.length
  ) {
    return bad(
      404,
      "Customer account not found."
    );
  }

  const approved =
    [
      "active",
      "approved"
    ].includes(
      String(
        profile[0].status ||
        ""
      ).toLowerCase()
    );

  if (!approved) {
    return bad(
      403,
      "Your account is awaiting administrator approval. Please wait until your account is approved before performing this action."
    );
  }

  const inserted =
    await sql`
      INSERT INTO deposit_requests (
        id,
        user_id,
        wallet_id,
        amount,
        currency,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${auth.user.id},
        ${walletId},
        ${amount},
        'USD',
        'pending',
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  return response(201, {
    success: true,
    message:
      "Deposit request submitted successfully.",
    request:
      inserted[0]
  });
}

/* =====================================================
   SEND
===================================================== */

async function createSend(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const body =
    await jsonBody(request);

  const amount =
    Number(
      body.amount
    );

  const recipient =
    String(
      body.recipient ||
      body.recipient_email ||
      body.email ||
      ""
    )
      .trim()
      .toLowerCase();

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid amount."
    );
  }

  if (!recipient) {
    return bad(
      400,
      "Recipient is required."
    );
  }

  const profile =
    await sql`
      SELECT
        status,
        kyc_status
      FROM profiles
      WHERE id =
        ${auth.user.id}
      LIMIT 1
    `;

  if (!profile.length) {
    return bad(
      404,
      "Customer account not found."
    );
  }

  const approved =
    [
      "active",
      "approved"
    ].includes(
      String(
        profile[0].status ||
        ""
      ).toLowerCase()
    );

  if (!approved) {
    return bad(
      403,
      "Your account is awaiting administrator approval. Please wait until your account is approved before performing this action."
    );
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${auth.user.id}
        AND LOWER(
          COALESCE(
            wallet_type,
            ''
          )
        ) = 'main'
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      400,
      "Main wallet not found."
    );
  }

  const wallet =
    walletRows[0];

  const balance =
    Number(
      wallet.balance || 0
    );

  if (balance < amount) {
    return bad(
      400,
      "Insufficient balance."
    );
  }

  const inserted =
    await sql`
      INSERT INTO send_requests (
        id,
        user_id,
        wallet_id,
        recipient,
        amount,
        currency,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${auth.user.id},
        ${wallet.id},
        ${recipient},
        ${amount},
        'USD',
        'pending',
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  return response(201, {
    success: true,
    message:
      "Send request submitted successfully.",
    request:
      inserted[0]
  });
}

/* =====================================================
   WITHDRAWAL ACCOUNT
===================================================== */

async function getWithdrawalAccount(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM withdrawal_accounts
      WHERE user_id =
        ${auth.user.id}
      ORDER BY
        updated_at DESC,
        created_at DESC
      LIMIT 1
    `;

  return ok({
    withdrawal_account:
      rows[0] || null
  });
}

/* =====================================================
   SAVE / UPDATE WITHDRAWAL ACCOUNT
===================================================== */

async function saveWithdrawalAccount(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const body =
    await jsonBody(request);

  const bankName =
    String(
      body.bank_name ||
      body.bankName ||
      ""
    ).trim();

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

  const bankCode =
    String(
      body.bank_code ||
      body.bankCode ||
      ""
    ).trim();

  if (
    !bankName ||
    !accountName ||
    !accountNumber
  ) {
    return bad(
      400,
      "Bank name, account name and account number are required."
    );
  }

  const existing =
    await sql`
      SELECT id
      FROM withdrawal_accounts
      WHERE user_id =
        ${auth.user.id}
      ORDER BY
        created_at DESC
      LIMIT 1
    `;

  let row;

  if (existing.length) {
    const updated =
      await sql`
        UPDATE withdrawal_accounts
        SET
          bank_name =
            ${bankName},
          account_name =
            ${accountName},
          account_number =
            ${accountNumber},
          bank_code =
            ${bankCode || null},
          updated_at =
            NOW()
        WHERE id =
          ${existing[0].id}
        RETURNING *
      `;

    row =
      updated[0];
  } else {
    const inserted =
      await sql`
        INSERT INTO withdrawal_accounts (
          id,
          user_id,
          bank_name,
          account_name,
          account_number,
          bank_code,
          created_at,
          updated_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${auth.user.id},
          ${bankName},
          ${accountName},
          ${accountNumber},
          ${bankCode || null},
          NOW(),
          NOW()
        )
        RETURNING *
      `;

    row =
      inserted[0];
  }

  return ok({
    message:
      "Withdrawal account saved successfully.",
    withdrawal_account:
      row
  });
}

/* =====================================================
   WITHDRAWAL REQUEST
===================================================== */

async function createWithdrawal(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const body =
    await jsonBody(request);

  const amount =
    Number(
      body.amount
    );

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid withdrawal amount."
    );
  }

  const account =
    await sql`
      SELECT *
      FROM withdrawal_accounts
      WHERE user_id =
        ${auth.user.id}
      ORDER BY
        updated_at DESC,
        created_at DESC
      LIMIT 1
    `;

  if (!account.length) {
    return response(409, {
      success: false,
      code:
        "WITHDRAWAL_ACCOUNT_REQUIRED",
      error:
        "Please add your withdrawal bank account details before making a withdrawal."
    });
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${auth.user.id}
        AND LOWER(
          COALESCE(
            wallet_type,
            ''
          )
        ) = 'main'
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      400,
      "Main wallet not found."
    );
  }

  const wallet =
    walletRows[0];

  const balance =
    Number(
      wallet.balance || 0
    );

  if (balance < amount) {
    return bad(
      400,
      "Insufficient balance."
    );
  }

  const inserted =
    await sql`
      INSERT INTO withdrawal_requests (
        id,
        user_id,
        wallet_id,
        amount,
        currency,
        bank_name,
        account_name,
        account_number,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${auth.user.id},
        ${wallet.id},
        ${amount},
        'USD',
        ${account[0].bank_name},
        ${account[0].account_name},
        ${account[0].account_number},
        'pending',
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  return response(201, {
    success: true,
    message:
      "Withdrawal request submitted successfully.",
    request:
      inserted[0]
  });
}

/* =====================================================
   INVESTMENT
===================================================== */

async function createInvestment(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const profile =
    await sql`
      SELECT
        status,
        kyc_status
      FROM profiles
      WHERE id =
        ${auth.user.id}
      LIMIT 1
    `;

  if (!profile.length) {
    return bad(
      404,
      "Customer account not found."
    );
  }

  const accountApproved =
    [
      "active",
      "approved"
    ].includes(
      String(
        profile[0].status ||
        ""
      ).toLowerCase()
    );

  if (!accountApproved) {
    return bad(
      403,
      "Your account is awaiting administrator approval. Please wait until your account is approved before performing this action."
    );
  }

  const kycApproved =
    String(
      profile[0].kyc_status ||
      ""
    ).toLowerCase() ===
    "approved";

  if (!kycApproved) {
    return response(403, {
      success: false,
      code:
        "KYC_REQUIRED",
      error:
        "KYC verification is required before making an investment.",
      kyc_required:
        true,
      kyc_status:
        profile[0].kyc_status ||
        "pending"
    });
  }

  const body =
    await jsonBody(request);

  const amount =
    Number(
      body.amount
    );

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return bad(
      400,
      "Enter a valid investment amount."
    );
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${auth.user.id}
        AND LOWER(
          COALESCE(
            wallet_type,
            ''
          )
        ) = 'main'
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      400,
      "Main wallet not found."
    );
  }

  const wallet =
    walletRows[0];

  if (
    Number(
      wallet.balance || 0
    ) < amount
  ) {
    return bad(
      400,
      "Insufficient balance."
    );
  }

  const inserted =
    await sql`
      INSERT INTO investments (
        id,
        user_id,
        wallet_id,
        amount,
        status,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${auth.user.id},
        ${wallet.id},
        ${amount},
        'pending',
        NOW(),
        NOW()
      )
      RETURNING *
    `;

  return response(201, {
    success: true,
    message:
      "Investment request submitted successfully.",
    investment:
      inserted[0]
  });
}

/* =====================================================
   ADMIN WALLET / CUSTOMER DATA
===================================================== */

async function adminCustomers(
  request
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const customers =
    await sql`
      SELECT
        p.*,
        COALESCE(
          (
            SELECT
              SUM(
                COALESCE(
                  w.balance,
                  0
                )
              )
            FROM wallets w
            WHERE w.user_id =
              p.id
          ),
          0
        ) AS total_balance
      FROM profiles p
      ORDER BY
        p.created_at DESC
    `;

  return ok({
    customers
  });
}

/* =====================================================
   ADMIN CUSTOMER WALLETS
===================================================== */

async function adminCustomerWallets(
  request,
  userId
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  if (!userId) {
    return bad(
      400,
      "Customer ID is required."
    );
  }

  await ensureUserWallets(
    userId
  );

  const wallets =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${userId}
      ORDER BY
        created_at ASC
    `;

  return ok({
    wallets
  });
}

/* =====================================================
   CUSTOMER DASHBOARD SUMMARY
===================================================== */

async function dashboardSummary(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const userId =
    auth.user.id;

  await ensureUserWallets(
    userId
  );

  const wallets =
    await sql`
      SELECT
        id,
        wallet_type,
        balance,
        currency,
        status,
        updated_at
      FROM wallets
      WHERE user_id =
        ${userId}
      ORDER BY
        created_at ASC
    `;

  const transactions =
    await sql`
      SELECT
        t.*
      FROM transactions t
      WHERE t.user_id =
        ${userId}
      ORDER BY
        t.created_at DESC
      LIMIT 20
    `;

  const investments =
    await sql`
      SELECT
        i.*
      FROM investments i
      WHERE i.user_id =
        ${userId}
      ORDER BY
        i.created_at DESC
      LIMIT 20
    `;

  const profile =
    await sql`
      SELECT
        id,
        email,
        first_name,
        last_name,
        username,
        status,
        kyc_status,
        email_verified_at
      FROM profiles
      WHERE id =
        ${userId}
      LIMIT 1
    `;

  return ok({
    profile:
      profile[0] || null,

    wallets,

    transactions,

    investments
  });
}

/* =====================================================
   ADMIN DASHBOARD STATS
===================================================== */

async function adminStats(
  request
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const customers =
    await sql`
      SELECT COUNT(*)::int AS count
      FROM profiles
    `;

  const activeCustomers =
    await sql`
      SELECT COUNT(*)::int AS count
      FROM profiles
      WHERE LOWER(
        COALESCE(status, '')
      ) IN (
        'active',
        'approved'
      )
    `;

  const investments =
    await sql`
      SELECT COUNT(*)::int AS count
      FROM investments
      WHERE LOWER(
        COALESCE(status, '')
      ) IN (
        'active',
        'approved',
        'running'
      )
    `;

  const pendingRequests =
    await sql`
      SELECT
        (
          SELECT COUNT(*)
          FROM deposit_requests
          WHERE LOWER(
            COALESCE(status, '')
          ) = 'pending'
        )
        +
        (
          SELECT COUNT(*)
          FROM withdrawal_requests
          WHERE LOWER(
            COALESCE(status, '')
          ) = 'pending'
        )
        +
        (
          SELECT COUNT(*)
          FROM send_requests
          WHERE LOWER(
            COALESCE(status, '')
          ) = 'pending'
        )
        AS count
    `;

  return ok({
    customers:
      customers[0]?.count || 0,

    activeCustomers:
      activeCustomers[0]?.count ||
      0,

    activeInvestments:
      investments[0]?.count ||
      0,

    investments:
      investments[0]?.count ||
      0,

    pendingRequests:
      Number(
        pendingRequests[0]?.count ||
        0
      )
  });
}

/* =====================================================
   ADMIN RECENT ACTIVITIES
===================================================== */

async function adminRecentActivities(
  request
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  let recentItems = [];

  try {
    const activityData =
      await sql`
        SELECT *
        FROM admin_activities
        ORDER BY
          created_at DESC
        LIMIT 50
      `;

    recentItems =
      activityData || [];
  } catch {
    recentItems = [];
  }

  return ok({
    activities:
      recentItems,

    recentActivities:
      recentItems,

    recent_items:
      recentItems
  });
}

/* =====================================================
   CUSTOMER CHAT
===================================================== */

async function customerChat(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  let messages = [];

  try {
    messages =
      await sql`
        SELECT *
        FROM chat_messages
        WHERE user_id =
          ${auth.user.id}
        ORDER BY
          created_at ASC
        LIMIT 500
      `;
  } catch (error) {
    /*
     * Keep the API alive if the deployment has
     * not yet created the optional chat table.
     */
    return ok({
      messages: [],
      chat_available: false,
      chat_error:
        error?.message ||
        "Customer chat is unavailable."
    });
  }

  return ok({
    messages,
    chat_available: true
  });
}

/* =====================================================
   SEND CUSTOMER CHAT MESSAGE
===================================================== */

async function sendCustomerChat(
  request
) {
  const auth =
    await authenticate(request);

  if (!auth.ok) {
    return bad(
      auth.status,
      auth.error
    );
  }

  const body =
    await jsonBody(request);

  const message =
    String(
      body.message ||
      body.text ||
      ""
    ).trim();

  if (!message) {
    return bad(
      400,
      "Message is required."
    );
  }

  try {
    const inserted =
      await sql`
        INSERT INTO chat_messages (
          id,
          user_id,
          sender_id,
          sender_type,
          message,
          created_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${auth.user.id},
          ${auth.user.id},
          'customer',
          ${message},
          NOW()
        )
        RETURNING *
      `;

    return response(201, {
      success: true,
      message:
        "Message sent successfully.",
      chat:
        inserted[0]
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to send message."
    );
  }
}

/* =====================================================
   ADMIN CHAT
===================================================== */

async function adminChat(
  request,
  userId
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  if (!userId) {
    return bad(
      400,
      "Customer ID is required."
    );
  }

  try {
    const messages =
      await sql`
        SELECT *
        FROM chat_messages
        WHERE user_id =
          ${userId}
        ORDER BY
          created_at ASC
        LIMIT 500
      `;

    return ok({
      messages
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to load customer chat."
    );
  }
}

/* =====================================================
   ADMIN SEND CHAT
===================================================== */

async function adminSendChat(
  request
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const body =
    await jsonBody(request);

  const userId =
    body.user_id ||
    body.userId;

  const message =
    String(
      body.message ||
      body.text ||
      ""
    ).trim();

  if (!userId) {
    return bad(
      400,
      "Customer ID is required."
    );
  }

  if (!message) {
    return bad(
      400,
      "Message is required."
    );
  }

  try {
    const inserted =
      await sql`
        INSERT INTO chat_messages (
          id,
          user_id,
          sender_id,
          sender_type,
          message,
          created_at
        )
        VALUES (
          ${crypto.randomUUID()},
          ${userId},
          ${admin.user.id},
          'admin',
          ${message},
          NOW()
        )
        RETURNING *
      `;

    return response(201, {
      success: true,
      message:
        "Admin message sent successfully.",
      chat:
        inserted[0]
    });
  } catch (error) {
    return bad(
      500,
      error?.message ||
        "Unable to send admin message."
    );
  }
}

/* =====================================================
   ADMIN DEPOSIT APPROVAL
===================================================== */

async function approveDeposit(
  request,
  id
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
      "Deposit request ID is required."
    );
  }

  const current =
    await sql`
      SELECT *
      FROM deposit_requests
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (!current.length) {
    return bad(
      404,
      "Deposit request not found."
    );
  }

  const requestRow =
    current[0];

  if (
    String(
      requestRow.status || ""
    ).toLowerCase() !==
    "pending"
  ) {
    return bad(
      400,
      "Deposit request is no longer pending."
    );
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE
        (
          id =
            ${requestRow.wallet_id}
          OR (
            user_id =
              ${requestRow.user_id}
            AND LOWER(
              COALESCE(
                wallet_type,
                ''
              )
            ) = 'main'
          )
        )
      ORDER BY
        CASE
          WHEN id =
            ${requestRow.wallet_id}
          THEN 0
          ELSE 1
        END
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

  const oldBalance =
    Number(
      wallet.balance || 0
    );

  const amount =
    Number(
      requestRow.amount || 0
    );

  const newBalance =
    oldBalance + amount;

  await sql`
    UPDATE wallets
    SET
      balance =
        ${newBalance},
      updated_at =
        NOW()
    WHERE id =
      ${wallet.id}
  `;

  const transactionId =
    crypto.randomUUID();

  await sql`
    INSERT INTO transactions (
      id,
      user_id,
      wallet_id,
      type,
      amount,
      currency,
      status,
      description,
      created_at,
      updated_at
    )
    VALUES (
      ${transactionId},
      ${requestRow.user_id},
      ${wallet.id},
      'deposit',
      ${amount},
      COALESCE(
        ${requestRow.currency},
        'USD'
      ),
      'completed',
      'Deposit approved by administrator',
      NOW(),
      NOW()
    )
  `;

  const updated =
    await sql`
      UPDATE deposit_requests
      SET
        status = 'approved',
        reviewed_at = NOW(),
        processed_at = NOW(),
        transaction_id =
          ${transactionId},
        updated_at = NOW()
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
    await sql`
      UPDATE wallets
      SET
        balance =
          ${oldBalance},
        updated_at =
          NOW()
      WHERE id =
        ${wallet.id}
    `;

    return bad(
      400,
      "Deposit could not be approved because the request is no longer pending."
    );
  }

  return ok({
    message:
      "Deposit approved successfully.",
    request:
      updated[0],
    wallet: {
      ...wallet,
      balance:
        newBalance
    },
    transaction_id:
      transactionId
  });
}

/* =====================================================
   ADMIN WITHDRAWAL APPROVAL
===================================================== */

async function approveWithdrawal(
  request,
  id
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
      "Withdrawal request ID is required."
    );
  }

  const current =
    await sql`
      SELECT *
      FROM withdrawal_requests
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (!current.length) {
    return bad(
      404,
      "Withdrawal request not found."
    );
  }

  const requestRow =
    current[0];

  if (
    String(
      requestRow.status || ""
    ).toLowerCase() !==
    "pending"
  ) {
    return bad(
      400,
      "Withdrawal request is no longer pending."
    );
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE id =
        ${requestRow.wallet_id}
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

  const oldBalance =
    Number(
      wallet.balance || 0
    );

  const amount =
    Number(
      requestRow.amount || 0
    );

  if (
    oldBalance < amount
  ) {
    return bad(
      400,
      "Insufficient wallet balance."
    );
  }

  const newBalance =
    oldBalance - amount;

  await sql`
    UPDATE wallets
    SET
      balance =
        ${newBalance},
      updated_at =
        NOW()
    WHERE id =
      ${wallet.id}
  `;

  const transactionId =
    crypto.randomUUID();

  await sql`
    INSERT INTO transactions (
      id,
      user_id,
      wallet_id,
      type,
      amount,
      currency,
      status,
      description,
      created_at,
      updated_at
    )
    VALUES (
      ${transactionId},
      ${requestRow.user_id},
      ${wallet.id},
      'withdrawal',
      ${amount},
      COALESCE(
        ${requestRow.currency},
        'USD'
      ),
      'completed',
      'Withdrawal approved by administrator',
      NOW(),
      NOW()
    )
  `;

  const updated =
    await sql`
      UPDATE withdrawal_requests
      SET
        status = 'approved',
        reviewed_at = NOW(),
        processed_at = NOW(),
        transaction_id =
          ${transactionId},
        updated_at = NOW()
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
    await sql`
      UPDATE wallets
      SET
        balance =
          ${oldBalance},
        updated_at =
          NOW()
      WHERE id =
        ${wallet.id}
    `;

    return bad(
      400,
      "Withdrawal could not be approved because the request is no longer pending."
    );
  }

  return ok({
    message:
      "Withdrawal approved successfully.",
    request:
      updated[0],
    wallet: {
      ...wallet,
      balance:
        newBalance
    },
    transaction_id:
      transactionId
  });
}

/* =====================================================
   ADMIN SEND APPROVAL
===================================================== */

async function approveSend(
  request,
  id
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
      "Send request ID is required."
    );
  }

  const current =
    await sql`
      SELECT *
      FROM send_requests
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (!current.length) {
    return bad(
      404,
      "Send request not found."
    );
  }

  const requestRow =
    current[0];

  if (
    String(
      requestRow.status || ""
    ).toLowerCase() !==
    "pending"
  ) {
    return bad(
      400,
      "Send request is no longer pending."
    );
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE id =
        ${requestRow.wallet_id}
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

  const oldBalance =
    Number(
      wallet.balance || 0
    );

  const amount =
    Number(
      requestRow.amount || 0
    );

  if (
    oldBalance < amount
  ) {
    return bad(
      400,
      "Insufficient wallet balance."
    );
  }

  const recipientRows =
    await sql`
      SELECT id
      FROM profiles
      WHERE LOWER(email) =
        LOWER(
          ${requestRow.recipient}
        )
      LIMIT 1
    `;

  if (!recipientRows.length) {
    return bad(
      404,
      "Recipient account not found."
    );
  }

  const recipientId =
    recipientRows[0].id;

  await ensureUserWallets(
    recipientId
  );

  const recipientWalletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE user_id =
        ${recipientId}
        AND LOWER(
          COALESCE(
            wallet_type,
            ''
          )
        ) = 'main'
      LIMIT 1
    `;

  if (!recipientWalletRows.length) {
    return bad(
      404,
      "Recipient main wallet not found."
    );
  }

  const recipientWallet =
    recipientWalletRows[0];

  const senderNewBalance =
    oldBalance - amount;

  const recipientNewBalance =
    Number(
      recipientWallet.balance ||
      0
    ) + amount;

  await sql`
    UPDATE wallets
    SET
      balance =
        ${senderNewBalance},
      updated_at =
        NOW()
    WHERE id =
      ${wallet.id}
  `;

  await sql`
    UPDATE wallets
    SET
      balance =
        ${recipientNewBalance},
      updated_at =
        NOW()
    WHERE id =
      ${recipientWallet.id}
  `;

  const transactionId =
    crypto.randomUUID();

  await sql`
    INSERT INTO transactions (
      id,
      user_id,
      wallet_id,
      type,
      amount,
      currency,
      status,
      description,
      created_at,
      updated_at
    )
    VALUES (
      ${transactionId},
      ${requestRow.user_id},
      ${wallet.id},
      'send',
      ${amount},
      COALESCE(
        ${requestRow.currency},
        'USD'
      ),
      'completed',
      ${`Send to ${requestRow.recipient}`},
      NOW(),
      NOW()
    )
  `;

  await sql`
    INSERT INTO transactions (
      id,
      user_id,
      wallet_id,
      type,
      amount,
      currency,
      status,
      description,
      created_at,
      updated_at
    )
    VALUES (
      ${crypto.randomUUID()},
      ${recipientId},
      ${recipientWallet.id},
      'receive',
      ${amount},
      COALESCE(
        ${requestRow.currency},
        'USD'
      ),
      'completed',
      'Funds received',
      NOW(),
      NOW()
    )
  `;

  const updated =
    await sql`
      UPDATE send_requests
      SET
        status = 'approved',
        reviewed_at = NOW(),
        processed_at = NOW(),
        transaction_id =
          ${transactionId},
        updated_at = NOW()
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
    await sql`
      UPDATE wallets
      SET
        balance =
          ${oldBalance},
        updated_at =
          NOW()
      WHERE id =
        ${wallet.id}
    `;

    await sql`
      UPDATE wallets
      SET
        balance =
          ${Number(
            recipientWallet.balance ||
            0
          )},
        updated_at =
          NOW()
      WHERE id =
        ${recipientWallet.id}
    `;

    return bad(
      400,
      "Send request could not be approved because the request is no longer pending."
    );
  }

  return ok({
    message:
      "Send approved successfully.",
    request:
      updated[0],
    transaction_id:
      transactionId
  });
}

/* =====================================================
   ADMIN DECLINE REQUEST
===================================================== */

async function declineRequest(
  request,
  type,
  id
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
      "Request ID is required."
    );
  }

  const table =
    type === "deposit"
      ? "deposit_requests"
      : type === "withdrawal"
        ? "withdrawal_requests"
        : "send_requests";

  const rows =
    await sql`
      SELECT *
      FROM ${sql(table)}
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (!rows.length) {
    return bad(
      404,
      "Request not found."
    );
  }

  if (
    String(
      rows[0].status || ""
    ).toLowerCase() !==
    "pending"
  ) {
    return bad(
      400,
      "Request is no longer pending."
    );
  }

  const updated =
    await sql`
      UPDATE ${sql(table)}
      SET
        status = 'declined',
        reviewed_at = NOW(),
        updated_at = NOW()
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
      "Request declined successfully.",
    request:
      updated[0]
  });
}

/* =====================================================
   ADMIN PENDING REQUESTS
===================================================== */

async function adminRequests(
  request
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  let deposits = [];
  let withdrawals = [];
  let sends = [];

  try {
    deposits =
      await sql`
        SELECT
          d.*,
          p.email,
          p.first_name,
          p.last_name
        FROM deposit_requests d
        LEFT JOIN profiles p
          ON p.id =
            d.user_id
        ORDER BY
          d.created_at DESC
        LIMIT 200
      `;
  } catch {}

  try {
    withdrawals =
      await sql`
        SELECT
          w.*,
          p.email,
          p.first_name,
          p.last_name
        FROM withdrawal_requests w
        LEFT JOIN profiles p
          ON p.id =
            w.user_id
        ORDER BY
          w.created_at DESC
        LIMIT 200
      `;
  } catch {}

  try {
    sends =
      await sql`
        SELECT
          s.*,
          p.email,
          p.first_name,
          p.last_name
        FROM send_requests s
        LEFT JOIN profiles p
          ON p.id =
            s.user_id
        ORDER BY
          s.created_at DESC
        LIMIT 200
      `;
  } catch {}

  return ok({
    deposits,
    withdrawals,
    sends,

    depositRequests:
      deposits,

    withdrawalRequests:
      withdrawals,

    sendRequests:
      sends
  });
}

/* =====================================================
   ADMIN INVESTMENTS
===================================================== */

async function adminInvestments(
  request
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const rows =
    await sql`
      SELECT
        i.*,
        p.email,
        p.first_name,
        p.last_name
      FROM investments i
      LEFT JOIN profiles p
        ON p.id =
          i.user_id
      ORDER BY
        i.created_at DESC
      LIMIT 500
    `;

  return ok({
    investments:
      rows
  });
}

/* =====================================================
   ADMIN APPROVE INVESTMENT
===================================================== */

async function approveInvestment(
  request,
  id
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const rows =
    await sql`
      SELECT *
      FROM investments
      WHERE id =
        ${id}
      LIMIT 1
    `;

  if (!rows.length) {
    return bad(
      404,
      "Investment not found."
    );
  }

  const investment =
    rows[0];

  if (
    String(
      investment.status || ""
    ).toLowerCase() !==
    "pending"
  ) {
    return bad(
      400,
      "Investment is no longer pending."
    );
  }

  const walletRows =
    await sql`
      SELECT *
      FROM wallets
      WHERE id =
        ${investment.wallet_id}
      LIMIT 1
    `;

  if (!walletRows.length) {
    return bad(
      404,
      "Investment wallet not found."
    );
  }

  const wallet =
    walletRows[0];

  const oldBalance =
    Number(
      wallet.balance || 0
    );

  const amount =
    Number(
      investment.amount || 0
    );

  if (
    oldBalance < amount
  ) {
    return bad(
      400,
      "Insufficient balance."
    );
  }

  const newBalance =
    oldBalance - amount;

  await sql`
    UPDATE wallets
    SET
      balance =
        ${newBalance},
      updated_at =
        NOW()
    WHERE id =
      ${wallet.id}
  `;

  const transactionId =
    crypto.randomUUID();

  await sql`
    INSERT INTO transactions (
      id,
      user_id,
      wallet_id,
      type,
      amount,
      currency,
      status,
      description,
      created_at,
      updated_at
    )
    VALUES (
      ${transactionId},
      ${investment.user_id},
      ${wallet.id},
      'investment',
      ${amount},
      'USD',
      'completed',
      'Investment approved by administrator',
      NOW(),
      NOW()
    )
  `;

  const updated =
    await sql`
      UPDATE investments
      SET
        status = 'active',
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
    await sql`
      UPDATE wallets
      SET
        balance =
          ${oldBalance},
        updated_at =
          NOW()
      WHERE id =
        ${wallet.id}
    `;

    return bad(
      400,
      "Investment could not be approved because the request is no longer pending."
    );
  }

  return ok({
    message:
      "Investment approved successfully.",
    investment:
      updated[0],
    transaction_id:
      transactionId
  });
}

/* =====================================================
   ADMIN PASSWORD RESET
===================================================== */

async function resetAdminPassword(
  request,
  id
) {
  const admin =
    await requireAdmin(request);

  if (!admin.ok) {
    return bad(
      admin.status,
      admin.error
    );
  }

  const body =
    await jsonBody(request);

  const password =
    String(
      body.password || ""
    );

  if (
    password.length < 6
  ) {
    return bad(
      400,
      "Password must be at least 6 characters."
    );
  }

  const passwordHash =
    await hashPassword(password);

  const updated =
    await sql`
      UPDATE auth_credentials
      SET
        password_hash =
          ${passwordHash},
        failed_login_attempts =
          0,
        locked_until =
          NULL,
        updated_at =
          NOW()
      WHERE user_id =
        ${id}
      RETURNING user_id
    `;

  if (!updated.length) {
    return bad(
      404,
      "Customer credentials not found."
    );
  }

  return ok({
    message:
      "Password reset successfully."
  });
}

/* =====================================================
   LOGOUT
===================================================== */

async function logout(
  request
) {
  const token =
    bearer(request);

  if (!token) {
    return ok({
      message:
        "Logged out."
    });
  }

  await sql`
    UPDATE user_sessions
    SET
      status = 'revoked',
      updated_at = NOW()
    WHERE
      session_token_hash =
        ${hashToken(token)}
      AND status = 'active'
  `;

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
    await sql`
      SELECT 1
    `;

    return ok({
      service:
        "CoinForest API",
      database:
        "connected",
      timestamp:
        new Date().toISOString()
    });
  } catch (error) {
    return response(503, {
      success: false,
      service:
        "CoinForest API",
      database:
        "disconnected",
      error:
        error?.message ||
        "Database unavailable."
    });
  }
}

/* =====================================================
   ROUTER
===================================================== */

async function router(
  request
) {
  const url =
    new URL(
      request.url
    );

  const method =
    request.method
      .toUpperCase();

  const path =
    url.pathname
      .replace(
        /\/+/g,
        "/"
      )
      .replace(
        /\/$/,
        ""
      ) || "/";

  if (
    method === "OPTIONS"
  ) {
    return response(
      204,
      {}
    );
  }

  try {

    /* =================================================
       HEALTH
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/health" ||
        path === "/health"
      )
    ) {
      return health();
    }

    /* =================================================
       REGISTER
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/auth/register" ||
        path === "/api/register" ||
        path === "/register"
      )
    ) {
      return register(
        await jsonBody(request)
      );
    }

    /* =================================================
       LOGIN
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/auth/login" ||
        path === "/api/login" ||
        path === "/login" ||
        path === "/api/customer/login"
      )
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
      const auth =
        await authenticate(
          request
        );

      if (!auth.ok) {
        return bad(
          auth.status,
          auth.error
        );
      }

      const updated =
        await sql`
          UPDATE profiles
          SET
            email_verified_at =
              COALESCE(
                email_verified_at,
                NOW()
              ),
            updated_at =
              NOW()
          WHERE id =
            ${auth.user.id}
          RETURNING *
        `;

      return ok({
        message:
          "Email verification status updated.",
        user:
          updated[0]
      });
    }

    /* =================================================
       LOGOUT
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/auth/logout" ||
        path === "/api/logout" ||
        path === "/logout"
      )
    ) {
      return logout(
        request
      );
    }

    /* =================================================
       CURRENT USER
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/auth/me" ||
        path === "/api/me" ||
        path === "/api/customer/me"
      )
    ) {
      return currentUser(
        request
      );
    }

    /* =================================================
       DASHBOARD
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/dashboard" ||
        path === "/api/dashboard" ||
        path === "/api/customer/summary"
      )
    ) {
      return dashboardSummary(
        request
      );
    }

    /* =================================================
       PROFILE
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/profile" ||
        path === "/api/profile"
      )
    ) {
      return customerProfile(
        request
      );
    }

    if (
      method === "PATCH" &&
      (
        path === "/api/customer/profile" ||
        path === "/api/profile"
      )
    ) {
      return updateCustomerProfile(
        request
      );
    }

    if (
      method === "PUT" &&
      (
        path === "/api/customer/profile" ||
        path === "/api/profile"
      )
    ) {
      return updateCustomerProfile(
        request
      );
    }

    /* =================================================
       KYC
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/kyc" ||
        path === "/api/customer/kyc/status" ||
        path === "/api/kyc/status"
      )
    ) {
      return customerKycStatus(
        request
      );
    }

    if (
      method === "POST" &&
      (
        path === "/api/customer/kyc" ||
        path === "/api/customer/kyc/apply" ||
        path === "/api/kyc/apply"
      )
    ) {
      return submitKyc(
        request
      );
    }

    /* =================================================
       WALLETS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/wallets" ||
        path === "/api/wallets" ||
        path === "/api/wallet"
      )
    ) {
      return getWallets(
        request
      );
    }

    const walletMatch =
      path.match(
        /^\/api\/(?:customer\/)?wallets\/([^/]+)$/
      );

    if (
      method === "GET" &&
      walletMatch
    ) {
      return getWallet(
        request,
        walletMatch[1]
      );
    }

    /* =================================================
       TRANSACTIONS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/transactions" ||
        path === "/api/transactions" ||
        path === "/api/customer/transaction"
      )
    ) {
      return customerTransactions(
        request
      );
    }

    /* =================================================
       DEPOSIT
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/customer/deposit" ||
        path === "/api/deposit"
      )
    ) {
      return createDeposit(
        request
      );
    }

    /* =================================================
       SEND
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/customer/send" ||
        path === "/api/send"
      )
    ) {
      return createSend(
        request
      );
    }

    /* =================================================
       WITHDRAWAL ACCOUNT
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/withdrawal-account" ||
        path === "/api/customer/withdrawal-account/details" ||
        path === "/api/withdrawal-account"
      )
    ) {
      return getWithdrawalAccount(
        request
      );
    }

    if (
      method === "POST" &&
      (
        path === "/api/customer/withdrawal-account" ||
        path === "/api/customer/withdrawal-account/details" ||
        path === "/api/withdrawal-account"
      )
    ) {
      return saveWithdrawalAccount(
        request
      );
    }

    if (
      method === "PUT" &&
      (
        path === "/api/customer/withdrawal-account" ||
        path === "/api/customer/withdrawal-account/details" ||
        path === "/api/withdrawal-account"
      )
    ) {
      return saveWithdrawalAccount(
        request
      );
    }

    /* =================================================
       WITHDRAW
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/customer/withdraw" ||
        path === "/api/withdraw"
      )
    ) {
      return createWithdrawal(
        request
      );
    }

    /* =================================================
       INVESTMENT
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/customer/invest" ||
        path === "/api/invest" ||
        path === "/api/customer/investment"
      )
    ) {
      return createInvestment(
        request
      );
    }

    /* =================================================
       CUSTOMER CHAT
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/customer/chat" ||
        path === "/api/chat"
      )
    ) {
      return customerChat(
        request
      );
    }

    if (
      method === "POST" &&
      (
        path === "/api/customer/chat" ||
        path === "/api/chat"
      )
    ) {
      return sendCustomerChat(
        request
      );
    }

    /* =================================================
       ADMIN STATS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/stats" ||
        path === "/api/admin/dashboard"
      )
    ) {
      return adminStats(
        request
      );
    }

    /* =================================================
       ADMIN RECENT ACTIVITIES
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/activities" ||
        path === "/api/admin/recent-activities" ||
        path === "/api/admin/recent"
      )
    ) {
      return adminRecentActivities(
        request
      );
    }

    /* =================================================
       ADMIN CUSTOMERS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/customers" ||
        path === "/api/customers"
      )
    ) {
      return adminCustomers(
        request
      );
    }

    /* =================================================
       ADMIN CUSTOMER WALLET
    ================================================= */

    const adminWalletMatch =
      path.match(
        /^\/api\/admin\/customers\/([^/]+)\/wallets$/
      );

    if (
      method === "GET" &&
      adminWalletMatch
    ) {
      return adminCustomerWallets(
        request,
        adminWalletMatch[1]
      );
    }

    /* =================================================
       ADMIN CUSTOMER UPDATE
    ================================================= */

    const adminCustomerMatch =
      path.match(
        /^\/api\/admin\/customers\/([^/]+)$/
      );

    if (
      (
        method === "PATCH" ||
        method === "PUT"
      ) &&
      adminCustomerMatch
    ) {
      return adminUpdateCustomer(
        request,
        adminCustomerMatch[1]
      );
    }

    /* =================================================
       ADMIN KYC
    ================================================= */

    const adminKycMatch =
      path.match(
        /^\/api\/admin\/customers\/([^/]+)\/kyc$/
      );

    if (
      (
        method === "PATCH" ||
        method === "PUT" ||
        method === "POST"
      ) &&
      adminKycMatch
    ) {
      return adminUpdateKyc(
        request,
        adminKycMatch[1]
      );
    }

    /* =================================================
       ADMIN WALLET ADJUSTMENT
    ================================================= */

    if (
      method === "POST" &&
      (
        path === "/api/admin/wallet/adjust" ||
        path === "/api/admin/wallets/adjust" ||
        path === "/api/admin/customer-wallet/adjust"
      )
    ) {
      return adminAdjustWallet(
        request
      );
    }

    /* =================================================
       ADMIN REQUESTS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/requests" ||
        path === "/api/admin/transaction-requests"
      )
    ) {
      return adminRequests(
        request
      );
    }

    /* =================================================
       ADMIN DEPOSIT APPROVE
    ================================================= */

    const depositApproveMatch =
      path.match(
        /^\/api\/admin\/deposits\/([^/]+)\/approve$/
      );

    if (
      method === "POST" &&
      depositApproveMatch
    ) {
      return approveDeposit(
        request,
        depositApproveMatch[1]
      );
    }

    /* =================================================
       ADMIN WITHDRAWAL APPROVE
    ================================================= */

    const withdrawalApproveMatch =
      path.match(
        /^\/api\/admin\/withdrawals\/([^/]+)\/approve$/
      );

    if (
      method === "POST" &&
      withdrawalApproveMatch
    ) {
      return approveWithdrawal(
        request,
        withdrawalApproveMatch[1]
      );
    }

    /* =================================================
       ADMIN SEND APPROVE
    ================================================= */

    const sendApproveMatch =
      path.match(
        /^\/api\/admin\/sends\/([^/]+)\/approve$/
      );

    if (
      method === "POST" &&
      sendApproveMatch
    ) {
      return approveSend(
        request,
        sendApproveMatch[1]
      );
    }

    /* =================================================
       ADMIN DECLINE DEPOSIT
    ================================================= */

    const depositDeclineMatch =
      path.match(
        /^\/api\/admin\/deposits\/([^/]+)\/decline$/
      );

    if (
      method === "POST" &&
      depositDeclineMatch
    ) {
      return declineRequest(
        request,
        "deposit",
        depositDeclineMatch[1]
      );
    }

    /* =================================================
       ADMIN DECLINE WITHDRAWAL
    ================================================= */

    const withdrawalDeclineMatch =
      path.match(
        /^\/api\/admin\/withdrawals\/([^/]+)\/decline$/
      );

    if (
      method === "POST" &&
      withdrawalDeclineMatch
    ) {
      return declineRequest(
        request,
        "withdrawal",
        withdrawalDeclineMatch[1]
      );
    }

    /* =================================================
       ADMIN DECLINE SEND
    ================================================= */

    const sendDeclineMatch =
      path.match(
        /^\/api\/admin\/sends\/([^/]+)\/decline$/
      );

    if (
      method === "POST" &&
      sendDeclineMatch
    ) {
      return declineRequest(
        request,
        "send",
        sendDeclineMatch[1]
      );
    }

    /* =================================================
       ADMIN CHAT
    ================================================= */

    const adminChatMatch =
      path.match(
        /^\/api\/admin\/chat\/([^/]+)$/
      );

    if (
      method === "GET" &&
      adminChatMatch
    ) {
      return adminChat(
        request,
        adminChatMatch[1]
      );
    }

    if (
      method === "POST" &&
      path === "/api/admin/chat"
    ) {
      return adminSendChat(
        request
      );
    }

    /* =================================================
       ADMIN INVESTMENTS
    ================================================= */

    if (
      method === "GET" &&
      (
        path === "/api/admin/investments" ||
        path === "/api/investments/admin"
      )
    ) {
      return adminInvestments(
        request
      );
    }

    const investmentApproveMatch =
      path.match(
        /^\/api\/admin\/investments\/([^/]+)\/approve$/
      );

    if (
      method === "POST" &&
      investmentApproveMatch
    ) {
      return approveInvestment(
        request,
        investmentApproveMatch[1]
      );
    }

    /* =================================================
       ADMIN PASSWORD RESET
    ================================================= */

    const passwordResetMatch =
      path.match(
        /^\/api\/admin\/customers\/([^/]+)\/password$/
      );

    if (
      method === "POST" &&
      passwordResetMatch
    ) {
      return resetAdminPassword(
        request,
        passwordResetMatch[1]
      );
    }

    /* =================================================
       NOT FOUND
    ================================================= */

    return response(404, {
      success: false,
      error:
        "API route not found.",
      path
    });

  } catch (error) {
    console.error(
      "API ERROR:",
      error
    );

    return response(
      500,
      {
        success: false,
        error:
          error?.message ||
          "Internal server error."
      }
    );
  }
}

/* =====================================================
   VERCEL / WEB HANDLER
===================================================== */

export default async function handler(
  req,
  res
) {
  try {
    const url =
      new URL(
        req.url,
        `http://${req.headers.host || "localhost"}`
      );

    const request =
      new Request(
        url.toString(),
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

    const result =
      await router(
        request
      );

    return writeWebResponse(
      res,
      result
    );

  } catch (error) {
    console.error(
      "HANDLER ERROR:",
      error
    );

    return writeWebResponse(
      res,
      response(
        500,
        {
          success: false,
          error:
            error?.message ||
            "Server error."
        }
      )
    );
  }
}

/* =====================================================
   END COINFOREST INDEX.JS
===================================================== */
