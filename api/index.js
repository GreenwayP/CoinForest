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

  return `https://${String(host).split(",")[0].trim()}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

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
          "CoinForest <greenwayexpress101@gmail.com>",
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
      NOW() + (${expiresMinutes} * INTERVAL '1 minute'),
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
    `${getSiteUrl(request)}/verify-email.html?token=${encodeURIComponent(token)}`;

  const firstName =
    String(user.first_name || "Customer")
      .trim();

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
            Coin<span style="color:#2ecc71;">Forest</span>
          </div>
        </div>

        <div style="padding:35px;">
          <h2>Confirm your account</h2>

          <p>Hello ${escapeHtml(firstName)},</p>

          <p style="line-height:1.7;">
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
            color:#7a8795;
          ">
            This confirmation link expires in 24 hours.
          </p>
        </div>
      </div>
    `
  });
}

async function register(request, body) {
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const firstName = String(body.first_name || "").trim();
  const lastName = String(body.last_name || "").trim();
  const username = String(body.username || "").trim();

  if (!email || !password) {
    return response(400, {
      success: false,
      error: "Email and password are required."
    });
  }

  if (!firstName) {
    return response(400, {
      success: false,
      error: "First name is required."
    });
  }

  if (!lastName) {
    return response(400, {
      success: false,
      error: "Last name is required."
    });
  }

  if (!username) {
    return response(400, {
      success: false,
      error: "Username is required."
    });
  }

  if (password.length < 6) {
    return response(400, {
      success: false,
      error:
        "Password must contain at least 6 characters."
    });
  }

  const existingEmail = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(email) = ${email}
    LIMIT 1
  `;

  if (existingEmail.length) {
    return response(409, {
      success: false,
      error:
        "An account with this email already exists."
    });
  }

  const existingUsername = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(username) = LOWER(${username})
    LIMIT 1
  `;

  if (existingUsername.length) {
    return response(409, {
      success: false,
      error: "That username is already in use."
    });
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

async function login(body) {
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");

  if (!email || !password) {
    return response(400, {
      success: false,
      error: "Email and password are required."
    });
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
    return response(401, {
      success: false,
      error: "Invalid email or password."
    });
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

    return response(401, {
      success: false,
      error: "Invalid email or password."
    });
  }

  if (!user.email_verified_at) {
    return response(403, {
      success: false,
      email_verified: false,
      error:
        "Please confirm your email address before signing in."
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

  return response(200, {
    success: true,
    message: "Login successful.",
    token,
    user: {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      role: user.role_name,
      email_verified: true
    }
  });
}

async function verifyEmail(token) {
  const cleanToken = String(token || "").trim();

  if (!cleanToken) {
    return response(400, {
      success: false,
      error: "Verification token is required."
    });
  }

  const tokenHash = hashToken(cleanToken);

  const result = await sql`
    SELECT
      t.id AS token_id,
      t.user_id
    FROM auth_email_tokens t
    WHERE t.token_hash = ${tokenHash}
      AND t.token_type = 'email_verification'
      AND t.used_at IS NULL
      AND t.expires_at > NOW()
    LIMIT 1
  `;

  if (!result.length) {
    return response(400, {
      success: false,
      error:
        "This verification link is invalid or has expired."
    });
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

  return response(200, {
    success: true,
    message:
      "Your email has been confirmed successfully."
  });
}

async function me(request) {
  const token = bearer(request);

  if (!token) {
    return response(401, {
      success: false,
      error: "Authentication required."
    });
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
    WHERE s.session_token_hash = ${tokenHash}
      AND s.status = 'active'
      AND s.expires_at > NOW()
    LIMIT 1
  `;

  if (!result.length) {
    return response(401, {
      success: false,
      error: "Invalid or expired session."
    });
  }

  await sql`
    UPDATE user_sessions
    SET
      last_activity_at = NOW(),
      updated_at = NOW()
    WHERE session_token_hash = ${tokenHash}
      AND status = 'active'
  `;

  const user = result[0];

  return response(200, {
    success: true,
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

async function logout(request) {
  const token = bearer(request);

  if (token) {
    await sql`
      UPDATE user_sessions
      SET
        status = 'revoked',
        revoked_at = NOW(),
        updated_at = NOW()
      WHERE session_token_hash = ${hashToken(token)}
        AND status = 'active'
    `;
  }

  return response(200, {
    success: true,
    message: "Logged out successfully."
  });
}

async function health() {
  return response(200, {
    success: true,
    message: "CoinForest API is running."
  });
}

function createWebRequest(req) {
  const protocol =
    String(
      req.headers["x-forwarded-proto"] || "https"
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

  const rawUrl = String(req.url || "/");

  const absoluteUrl =
    rawUrl.startsWith("http://") ||
    rawUrl.startsWith("https://")
      ? rawUrl
      : `${protocol}://${host}${rawUrl}`;

  const requestHeaders = new Headers();

  for (
    const [key, value]
    of Object.entries(req.headers || {})
  ) {
    if (Array.isArray(value)) {
      requestHeaders.set(
        key,
        value.join(", ")
      );
    } else if (value !== undefined) {
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
          !requestHeaders.has("content-type")
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

async function writeWebResponse(
  res,
  webResponse
) {
  if (res.headersSent) return;

  res.statusCode = webResponse.status;

  webResponse.headers.forEach(
    (value, key) => {
      res.setHeader(key, value);
    }
  );

  const body = await webResponse.text();

  res.end(body);
}

export default async function handler(req, res) {
  try {
    const request = createWebRequest(req);

    if (request.method === "OPTIONS") {
      res.statusCode = 204;

      res.setHeader(
        "Access-Control-Allow-Origin",
        "*"
      );

      res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization"
      );

      res.setHeader(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS"
      );

      res.end();
      return;
    }

    const url = new URL(request.url);
    const path = url.pathname;

    if (
      request.method === "GET" &&
      path === "/api/health"
    ) {
      return writeWebResponse(
        res,
        await health()
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/register"
    ) {
      const body = await request.json();

      return writeWebResponse(
        res,
        await register(request, body)
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/login"
    ) {
      const body = await request.json();

      return writeWebResponse(
        res,
        await login(body)
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/verify-email"
    ) {
      const body = await request.json();

      return writeWebResponse(
        res,
        await verifyEmail(body.token)
      );
    }

    if (
      request.method === "POST" &&
      path === "/api/auth/logout"
    ) {
      return writeWebResponse(
        res,
        await logout(request)
      );
    }

    if (
      request.method === "GET" &&
      path === "/api/auth/me"
    ) {
      return writeWebResponse(
        res,
        await me(request)
      );
    }

    return writeWebResponse(
      res,
      response(404, {
        success: false,
        error: "API route not found.",
        path
      })
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
        error: "Internal server error."
      })
    );
  }
      }
