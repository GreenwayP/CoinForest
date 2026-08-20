import crypto from "node:crypto";
import { neon } from "@neondatabase/serverless";

const sql = neon(process.env.DATABASE_URL);

const headers = {
  "Content-Type": "application/json",
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

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function createToken() {
  return crypto.randomBytes(48).toString("hex");
}

function bearer(request) {
  const value = request.headers.get("authorization") || "";
  return value.startsWith("Bearer ") ? value.slice(7).trim() : null;
}

function email(value) {
  return String(value || "").trim().toLowerCase();
}

async function register(body) {
  const e = email(body.email);
  const password = String(body.password || "");
  const firstName = String(body.first_name || "").trim();
  const lastName = String(body.last_name || "").trim();
  const username = String(body.username || "").trim();

  if (!e || !password) {
    return response(400, { success: false, error: "Email and password are required." });
  }

  if (password.length < 6) {
    return response(400, { success: false, error: "Password must contain at least 6 characters." });
  }

  const existing = await sql`
    SELECT id FROM profiles
    WHERE LOWER(email) = ${e}
    LIMIT 1
  `;

  if (existing.length) {
    return response(409, { success: false, error: "An account with this email already exists." });
  }

  const id = crypto.randomUUID();
  const fullName = [firstName, lastName].filter(Boolean).join(" ") || username || e.split("@")[0];

  await sql`
    INSERT INTO profiles
      (id, email, full_name, role, created_at, updated_at)
    VALUES
      (${id}, ${e}, ${fullName}, 'user', NOW(), NOW())
  `;

  await sql`
    INSERT INTO auth_credentials
      (user_id, password_hash, password_updated_at, failed_login_attempts, created_at, updated_at)
    VALUES
      (${id}, ${hash(password)}, NOW(), 0, NOW(), NOW())
  `;

  return response(201, {
    success: true,
    message: "Account created successfully.",
    user: {
      id,
      email: e,
      full_name: fullName,
      role: "user"
    }
  });
}

async function login(body) {
  const e = email(body.email);
  const password = String(body.password || "");

  if (!e || !password) {
    return response(400, { success: false, error: "Email and password are required." });
  }

  const result = await sql`
    SELECT
      p.id,
      p.email,
      p.full_name,
      p.role,
      a.password_hash,
      a.failed_login_attempts,
      a.locked_until
    FROM profiles p
    INNER JOIN auth_credentials a ON a.user_id = p.id
    WHERE LOWER(p.email) = ${e}
    LIMIT 1
  `;

  if (!result.length) {
    return response(401, { success: false, error: "Invalid email or password." });
  }

  const user = result[0];

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    return response(423, { success: false, error: "Account temporarily locked. Please try again later." });
  }

  if (hash(password) !== user.password_hash) {
    return response(401, { success: false, error: "Invalid email or password." });
  }

  const token = createToken();

  await sql`
    INSERT INTO user_sessions
      (user_id, session_token_hash, status, last_activity_at, expires_at, created_at, updated_at)
    VALUES
      (${user.id}, ${hash(token)}, 'active', NOW(), NOW() + INTERVAL '30 days', NOW(), NOW())
  `;

  return response(200, {
    success: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      full_name: user.full_name,
      role: user.role
    }
  });
}

async function me(request) {
  const token = bearer(request);

  if (!token) {
    return response(401, { success: false, error: "Authentication required." });
  }

  const result = await sql`
    SELECT p.id, p.email, p.full_name, p.role
    FROM user_sessions s
    INNER JOIN profiles p ON p.id = s.user_id
    WHERE s.session_token_hash = ${hash(token)}
      AND s.status = 'active'
      AND s.expires_at > NOW()
    LIMIT 1
  `;

  if (!result.length) {
    return response(401, { success: false, error: "Invalid or expired session." });
  }

  return response(200, {
    success: true,
    user: result[0]
  });
}

async function logout(request) {
  const token = bearer(request);

  if (token) {
    await sql`
      UPDATE user_sessions
      SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
      WHERE session_token_hash = ${hash(token)}
        AND status = 'active'
    `;
  }

  return response(200, {
    success: true,
    message: "Logged out successfully."
  });
}

async function health() {
  const result = await sql`SELECT NOW() AS current_time`;

  return response(200, {
    success: true,
    database: "connected",
    current_time: result[0].current_time
  });
}

export default async function handler(request) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers });
  }

  try {
    const path = url.pprofiles

    if (request.method === "GET" && path === "/health") {
      return health();
    }

    if (request.method === "POST" && path === "/auth/register") {
      return register(await request.json());
    }

    if (request.method === "POST" && path === "/auth/login") {
      return login(await request.json());
    }

    if (request.method === "POST" && path === "/auth/logout") {
      return logout(request);
    }

    if (request.method === "GET" && path === "/auth/me") {
      return me(request);
    }

    return response(404, {
      success: false,
      error: "API route not found."
    });

  } catch (error) {
    console.error(error);

    return response(500, {
      success: false,
      error: "Internal server error."
    });
  }
                          }
