import http from "node:http";
import crypto from "node:crypto";
import { promisify } from "node:util";
import { neon } from "@neondatabase/serverless";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error("DATABASE_URL is not configured.");
}

const sql = neon(databaseUrl);

const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

const scryptAsync = promisify(crypto.scrypt);

/* -------------------------------------------------------
   HELPERS
------------------------------------------------------- */

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS"
  });

  res.end(JSON.stringify(data));
}

function sendError(res, statusCode, message) {
  return sendJson(res, statusCode, {
    success: false,
    error: message
  });
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", chunk => {
      body += chunk.toString();

      if (body.length > 1024 * 1024) {
        reject(new Error("Request body too large."));
        req.destroy();
      }
    });

    req.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("Invalid JSON."));
      }
    });

    req.on("error", reject);
  });
}

function generateToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 128
  );
}

/* -------------------------------------------------------
   PASSWORD HASHING
------------------------------------------------------- */

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const derivedKey = await scryptAsync(
    password,
    salt,
    64
  );

  return `${salt}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(":")) {
    return false;
  }

  const [salt, keyHex] = storedHash.split(":");

  const derivedKey = await scryptAsync(
    password,
    salt,
    64
  );

  const storedKey = Buffer.from(keyHex, "hex");

  if (storedKey.length !== derivedKey.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    storedKey,
    derivedKey
  );
}

/* -------------------------------------------------------
   DATABASE
------------------------------------------------------- */

export async function testDatabaseConnection() {
  const result = await sql`
    SELECT NOW() AS current_time
  `;

  return result[0];
}

/* -------------------------------------------------------
   SESSION
------------------------------------------------------- */

async function createSession(userId, req) {
  const rawToken = generateToken();
  const tokenHash = hashToken(rawToken);

  await sql`
    INSERT INTO user_sessions (
      user_id,
      session_token_hash,
      ip_address,
      user_agent,
      device_name,
      status,
      last_activity_at,
      expires_at,
      created_at,
      updated_at
    )
    VALUES (
      ${userId},
      ${tokenHash},
      ${req.socket.remoteAddress || null},
      ${req.headers["user-agent"] || null},
      NULL,
      'active',
      NOW(),
      NOW() + INTERVAL '30 days',
      NOW(),
      NOW()
    )
  `;

  return rawToken;
}

async function revokeSession(token) {
  if (!token) {
    return;
  }

  const tokenHash = hashToken(token);

  await sql`
    UPDATE user_sessions
    SET
      status = 'revoked',
      revoked_at = NOW(),
      updated_at = NOW()
    WHERE session_token_hash = ${tokenHash}
      AND status = 'active'
  `;
}

async function getAuthenticatedUser(req) {
  const token = getBearerToken(req);

  if (!token) {
    return null;
  }

  const tokenHash = hashToken(token);

  const result = await sql`
    SELECT
      p.id,
      p.email,
      p.first_name,
      p.last_name,
      p.username,
      p.phone,
      p.country,
      p.city,
      p.postal_code,
      p.address,
      p.avatar_url,
      p.date_of_birth,
      p.gender,
      p.status,
      p.kyc_status,
      p.two_factor_enabled,
      r.name AS role,
      s.id AS session_id
    FROM user_sessions s
    INNER JOIN profiles p
      ON p.id = s.user_id
    INNER JOIN roles r
      ON r.id = p.role_id
    WHERE s.session_token_hash = ${tokenHash}
      AND s.status = 'active'
      AND s.expires_at > NOW()
      AND p.status = 'active'
    LIMIT 1
  `;

  if (result.length === 0) {
    return null;
  }

  await sql`
    UPDATE user_sessions
    SET
      last_activity_at = NOW(),
      updated_at = NOW()
    WHERE id = ${result[0].session_id}
  `;

  return result[0];
}

/* -------------------------------------------------------
   AUTHORIZATION
------------------------------------------------------- */

async function requireUser(req, res) {
  const user = await getAuthenticatedUser(req);

  if (!user) {
    sendError(res, 401, "Authentication required.");
    return null;
  }

  return user;
}

async function requireAdmin(req, res) {
  const user = await requireUser(req, res);

  if (!user) {
    return null;
  }

  if (user.role !== "admin") {
    sendError(
      res,
      403,
      "Administrator access required."
    );

    return null;
  }

  return user;
}

/* -------------------------------------------------------
   REGISTER
------------------------------------------------------- */

async function register(req, res) {
  const body = await readBody(req);

  const email = normalizeEmail(body.email);
  const password = body.password;

  const firstName = body.first_name
    ? String(body.first_name).trim()
    : null;

  const lastName = body.last_name
    ? String(body.last_name).trim()
    : null;

  const username = body.username
    ? String(body.username).trim()
    : null;

  if (!email) {
    return sendError(
      res,
      400,
      "Email is required."
    );
  }

  if (!validPassword(password)) {
    return sendError(
      res,
      400,
      "Password must contain 8 to 128 characters."
    );
  }

  const existing = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(email) = ${email}
    LIMIT 1
  `;

  if (existing.length > 0) {
    return sendError(
      res,
      409,
      "An account with this email already exists."
    );
  }

  const roleResult = await sql`
    SELECT id
    FROM roles
    WHERE name = 'user'
    LIMIT 1
  `;

  if (roleResult.length === 0) {
    return sendError(
      res,
      500,
      "Default user role is not configured."
    );
  }

  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

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
      created_at,
      updated_at
    )
    VALUES (
      ${userId},
      ${roleResult[0].id},
      ${firstName},
      ${lastName},
      ${username},
      ${email},
      'active',
      'not_verified',
      false,
      NOW(),
      NOW()
    )
  `;

  try {
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
        ${userId},
        ${passwordHash},
        NOW(),
        0,
        NULL,
        NOW(),
        NOW()
      )
    `;
  } catch (error) {
    await sql`
      DELETE FROM profiles
      WHERE id = ${userId}
    `;

    throw error;
  }

  return sendJson(res, 201, {
    success: true,
    message: "Account created successfully.",
    user: {
      id: userId,
      email,
      first_name: firstName,
      last_name: lastName,
      role: "user",
      status: "active",
      kyc_status: "not_verified"
    }
  });
}

/* -------------------------------------------------------
   LOGIN
------------------------------------------------------- */

async function login(req, res) {
  const body = await readBody(req);

  const email = normalizeEmail(body.email);
  const password = body.password;

  if (!email || !password) {
    return sendError(
      res,
      400,
      "Email and password are required."
    );
  }

  const result = await sql`
    SELECT
      p.id,
      p.email,
      p.first_name,
