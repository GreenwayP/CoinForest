import crypto from "node:crypto";
import { neon } from "@neondatabase/serverless";

const sql = neon(process.env.DATABASE_URL);

const headers = {
  "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

function response(status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

/* =====================================================
   PASSWORD HASHING
===================================================== */

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

    if (!salt || !key) {
      return false;
    }

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

/* =====================================================
   GENERAL HELPERS
===================================================== */

function createToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function bearer(request) {
  const value =
    request.headers.get("authorization") || "";

  if (!value.startsWith("Bearer ")) {
    return null;
  }

  return value.slice(7).trim();
}

/* =====================================================
   SITE URL
===================================================== */

function getSiteUrl(request) {
  const forwardedHost =
    request.headers.get("x-forwarded-host");

  const host =
    forwardedHost ||
    request.headers.get("host");

  const forwardedProto =
    request.headers.get("x-forwarded-proto");

  const protocol =
    forwardedProto ||
    "https";

  if (!host) {
    return "https://coinforest.vercel.app";
  }

  return `${protocol}://${host}`;
}

/* =====================================================
   RESEND EMAIL
===================================================== */

async function sendEmail({
  to,
  subject,
  html
}) {
  const apiKey =
    process.env.RESEND_API_KEY;

  if (!apiKey) {
    throw new Error(
      "RESEND_API_KEY is not configured."
    );
  }

  const responseFromResend =
    await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",

        headers: {
          "Authorization":
            `Bearer ${apiKey}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          from:
            "CoinForest <greenwayexpress101@gmail.com>",

          to: [to],

          subject,

          html
        })
      }
    );

  const data =
    await responseFromResend.json();

  if (!responseFromResend.ok) {
    console.error(
      "Resend error:",
      data
    );

    throw new Error(
      data?.message ||
      data?.error ||
      "Unable to send email."
    );
  }

  return data;
}

/* =====================================================
   EMAIL TOKEN CREATION
===================================================== */

async function createEmailToken(
  userId,
  tokenType,
  expiresMinutes
) {
  const rawToken =
    createToken();

  const tokenHash =
    hashToken(rawToken);

  await sql`
    UPDATE auth_email_tokens
    SET used_at = NOW()
    WHERE user_id = ${userId}
      AND token_type = ${tokenType}
      AND used_at IS NULL
  `;

  await sql`
    INSERT INTO auth_email_tokens (
      user_id,
      token_hash,
      token_type,
      expires_at,
      created_at
    )
    VALUES (
      ${userId},
      ${tokenHash},
      ${tokenType},
      NOW() + (${expiresMinutes} * INTERVAL '1 minute'),
      NOW()
    )
  `;

  return rawToken;
}

/* =====================================================
   SEND VERIFICATION EMAIL
===================================================== */

async function sendVerificationEmail(
  request,
  user
) {
  const token =
    await createEmailToken(
      user.id,
      "email_verification",
      60 * 24
    );

  const siteUrl =
    getSiteUrl(request);

  const verificationUrl =
    `${siteUrl}/verify-email.html?token=${encodeURIComponent(token)}`;

  const firstName =
    String(user.full_name || "Customer")
      .trim()
      .split(/\s+/)[0];

  return sendEmail({
    to: user.email,

    subject:
      "Confirm your CoinForest account",

    html: `
      <!DOCTYPE html>
      <html>
      <body style="
        margin:0;
        padding:0;
        background:#f4f7fa;
        font-family:Arial,Helvetica,sans-serif;
        color:#172033;
      ">

        <div style="
          max-width:600px;
          margin:40px auto;
          background:#ffffff;
          border-radius:18px;
          overflow:hidden;
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
              Coin<span style="color:#2ecc71;">Forest</span>
            </div>

          </div>

          <div style="padding:35px;">

            <h2 style="
              margin-top:0;
              color:#10233a;
            ">
              Confirm your account
            </h2>

            <p style="
              line-height:1.7;
              color:#5d6b7a;
            ">
              Hello ${escapeHtml(firstName)},
            </p>

            <p style="
              line-height:1.7;
              color:#5d6b7a;
            ">
              Thank you for creating your CoinForest account.
              Please confirm your email address to activate
              your account.
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
              line-height:1.6;
              color:#7a8795;
            ">
              This confirmation link expires in 24 hours.
            </p>

            <p style="
              font-size:13px;
              line-height:1.6;
              color:#7a8795;
            ">
              If you did not create this account, you can
              safely ignore this email.
            </p>

          </div>

        </div>

      </body>
      </html>
    `
  });
}

/* =====================================================
   PASSWORD RESET EMAIL
===================================================== */

async function sendPasswordResetEmail(
  request,
  user
) {
  const token =
    await createEmailToken(
      user.id,
      "password_reset",
      30
    );

  const siteUrl =
    getSiteUrl(request);

  const resetUrl =
    `${siteUrl}/reset-password.html?token=${encodeURIComponent(token)}`;

  const firstName =
    String(user.full_name || "Customer")
      .trim()
      .split(/\s+/)[0];

  return sendEmail({
    to: user.email,

    subject:
      "Reset your CoinForest password",

    html: `
      <!DOCTYPE html>
      <html>
      <body style="
        margin:0;
        padding:0;
        background:#f4f7fa;
        font-family:Arial,Helvetica,sans-serif;
        color:#172033;
      ">

        <div style="
          max-width:600px;
          margin:40px auto;
          background:#ffffff;
          border-radius:18px;
          overflow:hidden;
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
              Coin<span style="color:#2ecc71;">Forest</span>
            </div>

          </div>

          <div style="padding:35px;">

            <h2 style="
              margin-top:0;
              color:#10233a;
            ">
              Reset your password
            </h2>

            <p style="
              line-height:1.7;
              color:#5d6b7a;
            ">
              Hello ${escapeHtml(firstName)},
            </p>

            <p style="
              line-height:1.7;
              color:#5d6b7a;
            ">
              We received a request to reset your CoinForest
              password.
            </p>

            <div style="
              text-align:center;
              margin:30px 0;
            ">

              <a
                href="${resetUrl}"
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
                Reset My Password
              </a>

            </div>

            <p style="
              font-size:13px;
              line-height:1.6;
              color:#7a8795;
            ">
              This password-reset link expires in 30 minutes.
            </p>

            <p style="
              font-size:13px;
              line-height:1.6;
              color:#7a8795;
            ">
              If you did not request a password reset, you can
              safely ignore this email.
            </p>

          </div>

        </div>

      </body>
      </html>
    `
  });
}

/* =====================================================
   BASIC HTML ESCAPING
===================================================== */

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* =====================================================
   REGISTER
===================================================== */

async function register(request, body) {
  const e =
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

  if (!e || !password) {
    return response(400, {
      success:false,
      error:
        "Email and password are required."
    });
  }

  if (!firstName) {
    return response(400, {
      success:false,
      error:"First name is required."
    });
  }

  if (!lastName) {
    return response(400, {
      success:false,
      error:"Last name is required."
    });
  }

  if (!username) {
    return response(400, {
      success:false,
      error:"Username is required."
    });
  }

  if (password.length < 6) {
    return response(400, {
      success:false,
      error:
        "Password must contain at least 6 characters."
    });
  }

  const existingEmail =
    await sql`
      SELECT id
      FROM profiles
      WHERE LOWER(email) = ${e}
      LIMIT 1
    `;

  if (existingEmail.length > 0) {
    return response(409, {
      success:false,
      error:
        "An account with this email already exists."
    });
  }

  const existingUsername =
    await sql`
      SELECT id
      FROM profiles
      WHERE LOWER(username) =
        LOWER(${username})
      LIMIT 1
    `;

  if (existingUsername.length > 0) {
    return response(409, {
      success:false,
      error:
        "That username is already in use."
    });
  }

  const id =
    crypto.randomUUID();

  const fullName =
    [firstName, lastName]
      .filter(Boolean)
      .join(" ");

  const passwordHash =
    hashPassword(password);

  await sql`
    INSERT INTO profiles (
      id,
      email,
      full_name,
      username,
      role,
      email_verified_at,
      created_at,
      updated_at
    )
    VALUES (
      ${id},
      ${e},
      ${fullName},
      ${username},
      'user',
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
      created_at,
      updated_at
    )
    VALUES (
      ${id},
      ${passwordHash},
      NOW(),
      0,
      NOW(),
      NOW()
    )
  `;

  const user = {
    id,
    email:e,
    full_name:fullName
  };

  try {
    await sendVerificationEmail(
      request,
      user
    );
  } catch (emailError) {
    console.error(
      "Verification email error:",
      emailError
    );

    return response(201, {
      success:true,
      email_sent:false,
      message:
        "Account created, but the confirmation email could not be sent. Please request another verification email.",
      user:{
        id,
        email:e,
        first_name:firstName,
        last_name:lastName,
        username,
        full_name:fullName,
        role:"user"
      }
    });
  }

  return response(201, {
    success:true,
    email_sent:true,
    message:
      "Account created. Please check your email to confirm your account.",
    user:{
      id,
      email:e,
      first_name:firstName,
      last_name:lastName,
      username,
      full_name:fullName,
      role:"user"
    }
  });
}

/* =====================================================
   LOGIN
===================================================== */

async function login(body) {
  const e =
    normalizeEmail(body.email);

  const password =
    String(body.password || "");

  if (!e || !password) {
    return response(400, {
      success:false,
      error:
        "Email and password are required."
    });
  }

  const result =
    await sql`
      SELECT
        p.id,
        p.email,
        p.full_name,
        p.username,
        p.role,
        p.email_verified_at,
        a.password_hash,
        a.failed_login_attempts,
        a.locked_until
      FROM profiles p
      INNER JOIN auth_credentials a
        ON a.user_id = p.id
      WHERE LOWER(p.email) = ${e}
      LIMIT 1
    `;

  if (result.length === 0) {
    return response(401, {
      success:false,
      error:
        "Invalid email or password."
    });
  }

  const user =
    result[0];

  if (
    user.locked_until &&
    new Date(user.locked_until) >
      new Date()
  ) {
    return response(423, {
      success:false,
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
            NOW() + INTERVAL '15 minutes',
          updated_at = NOW()
        WHERE user_id = ${user.id}
      `;

      return response(423, {
        success:false,
        error:
          "Too many failed login attempts. Account temporarily locked."
      });
    }

    await sql`
      UPDATE auth_credentials
      SET
        failed_login_attempts =
          ${attempts},
        updated_at = NOW()
      WHERE user_id = ${user.id}
    `;

    return response(401, {
      success:false,
      error:
        "Invalid email or password."
    });
  }

  if (!user.email_verified_at) {
    return response(403, {
      success:false,
      error:
        "Please confirm your email address before signing in.",
      email_verified:false
    });
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
      user_id,
      session_token_hash,
      status,
      last_activity_at,
      expires_at,
      created_at,
      updated_at
    )
    VALUES (
      ${user.id},
      ${hashToken(token)},
      'active',
      NOW(),
      NOW() + INTERVAL '30 days',
      NOW(),
      NOW()
    )
  `;

  return response(200, {
    success:true,
    message:"Login successful.",
    token,
    user:{
      id:user.id,
      email:user.email,
      full_name:user.full_name,
      username:user.username,
      role:user.role,
      email_verified:true
    }
  });
}

/* =====================================================
   VERIFY EMAIL
===================================================== */

async function verifyEmail(token) {
  const cleanToken =
    String(token || "").trim();

  if (!cleanToken) {
    return response(400, {
      success:false,
      error:"Verification token is required."
    });
  }

  const tokenHash =
    hashToken(cleanToken);

  const result =
    await sql`
      SELECT
        t.id AS token_id,
        t.user_id,
        p.email,
        p.full_name
      FROM auth_email_tokens t
      INNER JOIN profiles p
        ON p.id = t.user_id
      WHERE t.token_hash = ${tokenHash}
        AND t.token_type =
          'email_verification'
        AND t.used_at IS NULL
        AND t.expires_at > NOW()
      LIMIT 1
    `;

  if (result.length === 0) {
    return response(400, {
      success:false,
      error:
        "This verification link is invalid or has expired."
    });
  }

  const item =
    result[0];

  await sql`
    UPDATE profiles
    SET
      email_verified_at = NOW(),
      updated_at = NOW()
    WHERE id = ${item.user_id}
  `;

  await sql`
    UPDATE auth_email_tokens
    SET
      used_at = NOW()
    WHERE id = ${item.token_id}
  `;

  return response(200, {
    success:true,
    message:
      "Your email has been confirmed successfully."
  });
}

/* =====================================================
   RESEND VERIFICATION
===================================================== */

async function resendVerification(
  request,
  body
) {
  const e =
    normalizeEmail(body.email);

  if (!e) {
    return response(400, {
      success:false,
      error:"Email address is required."
    });
  }

  const result =
    await sql`
      SELECT
        id,
        email,
        full_name,
        email_verified_at
      FROM profiles
      WHERE LOWER(email) = ${e}
      LIMIT 1
    `;

  /*
     Do not reveal whether an email
     exists in the database.
  */

  if (
    result.length === 0 ||
    result[0].email_verified_at
  ) {
    return response(200, {
      success:true,
      message:
        "If the account exists and still needs verification, a confirmation email has been sent."
    });
  }

  try {
    await sendVerificationEmail(
      request,
      result[0]
    );
  } catch (error) {
    console.error(
      "Resend verification error:",
      error
    );
  }

  return response(200, {
    success:true,
    message:
      "If the account exists and still needs verification, a confirmation email has been sent."
  });
}

/* =====================================================
   FORGOT PASSWORD
===================================================== */

async function forgotPassword(
  request,
  body
) {
  const e =
    normalizeEmail(body.email);

  if (!e) {
    return response(400, {
      success:false,
      error:"Email address is required."
    });
  }

  const result =
    await sql`
      SELECT
        id,
        email,
        full_name
      FROM profiles
      WHERE LOWER(email) = ${e}
      LIMIT 1
    `;

  /*
     Always return the same message.
     This prevents email-account discovery.
  */

  if (result.length === 0) {
    return response(200, {
      success:true,
      message:
        "If an account exists with that email, a password reset link has been sent."
    });
  }

  try {
    await sendPasswordResetEmail(
      request,
      result[0]
    );
  } catch (error) {
    console.error(
      "Password reset email error:",
      error
    );
  }

  return response(200, {
    success:true,
    message:
      "If an account exists with that email, a password reset link has been sent."
  });
}

/* =====================================================
   RESET PASSWORD
===================================================== */

async function resetPassword(
  body
) {
  const token =
    String(body.token || "").trim();

  const password =
    String(body.password || "");

  const confirmPassword =
    String(
      body.confirm_password || ""
    );

  if (!token) {
    return response(400, {
      success:false,
      error:"Reset token is required."
    });
  }

  if (password.length < 6) {
    return response(400, {
      success:false,
      error:
        "Password must contain at least 6 characters."
    });
  }

  if (password !== confirmPassword) {
    return response(400, {
      success:false,
      error:"Passwords do not match."
    });
  }

  const tokenHash =
    hashToken(token);

  const result =
    await sql`
      SELECT
        t.id AS token_id,
        t.user_id
      FROM auth_email_tokens t
      WHERE t.token_hash = ${tokenHash}
        AND t.token_type =
          'password_reset'
        AND t.used_at IS NULL
        AND t.expires_at > NOW()
      LIMIT 1
    `;

  if (result.length === 0) {
    return response(400, {
      success:false,
      error:
        "This password reset link is invalid or has expired."
    });
  }

  const item =
    result[0];

  const passwordHash =
    hashPassword(password);

  await sql`
    UPDATE auth_credentials
    SET
      password_hash = ${passwordHash},
      password_updated_at = NOW(),
      failed_login_attempts = 0,
      locked_until = NULL,
      updated_at = NOW()
    WHERE user_id = ${item.user_id}
  `;

  await sql`
    UPDATE auth_email_tokens
    SET
      used_at = NOW()
    WHERE id = ${item.token_id}
  `;

  /*
     Revoke existing sessions after
     a successful password reset.
  */

  await sql`
    UPDATE user_sessions
    SET
      status = 'revoked',
      revoked_at = NOW(),
      updated_at = NOW()
    WHERE user_id = ${item.user_id}
      AND status = 'active'
  `;

  return response(200, {
    success:true,
    message:
      "Your password has been reset successfully."
  });
}

/* =====================================================
   CURRENT USER
===================================================== */

async function me(request) {
  const token =
    bearer(request);

  if (!token) {
    return response(401, {
      success:false,
      error:"Authentication required."
    });
  }

  const tokenHash =
    hashToken(token);

  const result =
    await sql`
      SELECT
        p.id,
        p.email,
        p.full_name,
        p.username,
        p.role,
        p.email_verified_at
      FROM user_sessions s
      INNER JOIN profiles p
        ON p.id = s.user_id
      WHERE s.session_token_hash =
        ${tokenHash}
        AND s.status = 'active'
        AND s.expires_at > NOW()
      LIMIT 1
    `;

  if (result.length === 0) {
    return response(401, {
      success:false,
      error:
        "Invalid or expired session."
    });
  }

  await sql`
    UPDATE user_sessions
    SET
      last_activity_at = NOW(),
      updated_at = NOW()
    WHERE session_token_hash =
      ${tokenHash}
      AND status = 'active'
  `;

  return response(200, {
    success:true,
    user:result[0]
  });
}

/* =====================================================
   LOGOUT
===================================================== */

async function logout(request) {
  const token =
    bearer(request);

  if (token) {
    await sql`
      UPDATE user_sessions
      SET
        status = 'revoked',
        revoked_at = NOW(),
        updated_at = NOW()
      WHERE session_token_hash =
        ${hashToken(token)}
        AND status = 'active'
    `;
  }

  return response(200, {
    success:true,
    message:
      "Logged out successfully."
  });
}

/* =====================================================
   HEALTH
===================================================== */

async function health() {
  const result =
    await sql`
      SELECT NOW() AS current_time
    `;

  return response(200, {
    success:true,
    database:"connected",
    current_time:
      result[0].current_time
  });
}

/* =====================================================
   ROUTER
===================================================== */

export default async function handler(
  request
) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status:204,
      headers
    });
  }

  try {
    const url =
      new URL(request.url);

    const path =
      url.pathname;

    if (
      request.method === "GET" &&
      path === "/api/health"
    ) {
      return await health();
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/register"
    ) {
      const body =
        await request.json();

      return await register(
        request,
        body
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/login"
    ) {
      const body =
        await request.json();

      return await login(body);
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/verify-email"
    ) {
      const body =
        await request.json();

      return await verifyEmail(
        body.token
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/resend-verification"
    ) {
      const body =
        await request.json();

      return await resendVerification(
        request,
        body
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/forgot-password"
    ) {
      const body =
        await request.json();

      return await forgotPassword(
        request,
        body
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/reset-password"
    ) {
      const body =
        await request.json();

      return await resetPassword(body);
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/logout"
    ) {
      return await logout(request);
    }

    if (
      request.method === "GET" &&
      path === "/api/auth/me"
    ) {
      return await me(request);
    }

    return response(404, {
      success:false,
      error:"API route not found.",
      path
    });

  } catch (error) {
    console.error(
      "CoinForest API error:",
      error
    );

    return response(500, {
      success:false,
      error:
        "Internal server error."
    });
  }
      }
