import http from "node:http";
import crypto from "node:crypto";
import { neon } from "@neondatabase/serverless";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error("DATABASE_URL is not configured.");
}

const sql = neon(databaseUrl);

const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;

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

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
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
  return typeof password === "string" && password.length >= 6;
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

async function createSession(userId) {
  const rawToken = generateToken();
  const tokenHash = hashToken(rawToken);

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
      ${userId},
      ${tokenHash},
      'active',
      NOW(),
      NOW() + INTERVAL '30 days',
      NOW(),
      NOW()
    )
  `;

  return rawToken;
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
    sendError(res, 403, "Administrator access required.");
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
    return sendError(res, 400, "Email is required.");
  }

  if (!validPassword(password)) {
    return sendError(
      res,
      400,
      "Password must contain at least 6 characters."
    );
  }

  const existing = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(email) = ${email}
    LIMIT 1
  `;

  if (existing.length > 0) {
    return sendError(res, 409, "An account with this email already exists.");
  }

  const userId = crypto.randomUUID();

  const roleResult = await sql`
    SELECT id
    FROM roles
    WHERE name = 'user'
    LIMIT 1
  `;

  if (roleResult.length === 0) {
    return sendError(res, 500, "Default user role is not configured.");
  }

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

  /*
    The current profiles schema does not contain a password_hash column.

    Authentication password storage should eventually be moved to a
    dedicated authentication system/table rather than putting passwords
    directly into profiles.

    For this first foundation step we create the user/profile structure
    without altering your existing database schema.
  */

  return sendJson(res, 201, {
    success: true,
    message: "Account created successfully.",
    user: {
      id: userId,
      email,
      first_name: firstName,
      last_name: lastName,
      role: "user",
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
    return sendError(res, 400, "Email and password are required.");
  }

  /*
    Authentication credentials are not yet stored in the current
    profiles schema.

    This endpoint therefore checks that the account exists and returns
    a clear response instead of pretending authentication is complete.
  */

  const result = await sql`
    SELECT
      p.id,
      p.email,
      p.first_name,
      p.last_name,
      p.username,
      p.status,
      p.kyc_status,
      r.name AS role
    FROM profiles p
    INNER JOIN roles r
      ON r.id = p.role_id
    WHERE LOWER(p.email) = ${email}
    LIMIT 1
  `;

  if (result.length === 0) {
    return sendError(res, 401, "Invalid email or password.");
  }

  if (result[0].status !== "active") {
    return sendError(res, 403, "This account is not active.");
  }

  return sendError(
    res,
    501,
    "Authentication credentials are not configured yet. The account exists, but password authentication must be connected before login can be enabled."
  );
}

/* -------------------------------------------------------
   LOGOUT
------------------------------------------------------- */

async function logout(req, res) {
  const token = getBearerToken(req);

  if (!token) {
    return sendJson(res, 200, {
      success: true,
      message: "Already logged out."
    });
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

  return sendJson(res, 200, {
    success: true,
    message: "Logged out successfully."
  });
}

/* -------------------------------------------------------
   CURRENT USER
------------------------------------------------------- */

async function currentUser(req, res) {
  const user = await requireUser(req, res);

  if (!user) {
    return;
  }

  return sendJson(res, 200, {
    success: true,
    user
  });
}

/* -------------------------------------------------------
   ADMIN CHECK
------------------------------------------------------- */

async function adminMe(req, res) {
  const user = await requireAdmin(req, res);

  if (!user) {
    return;
  }

  return sendJson(res, 200, {
    success: true,
    user
  });
}

/* -------------------------------------------------------
   DATABASE HEALTH
------------------------------------------------------- */

async function databaseHealth(req, res) {
  try {
    const result = await testDatabaseConnection();

    return sendJson(res, 200, {
      success: true,
      database: "connected",
      current_time: result.current_time
    });
  } catch (error) {
    console.error("Database health error:", error);

    return sendError(
      res,
      500,
      "Database connection failed."
    );
  }
}

/* -------------------------------------------------------
   ROUTER
------------------------------------------------------- */

async function handleRequest(req, res) {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS"
    });

    res.end();
    return;
  }

  const url = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  try {
    if (req.method === "GET" && url.pathname === "/api/health") {
      return await databaseHealth(req, res);
    }

    if (req.method === "POST" && url.pathname === "/api/auth/register") {
      return await register(req, res);
    }

    if (req.method === "POST" && url.pathname === "/api/auth/login") {
      return await login(req, res);
    }

    if (req.method === "POST" && url.pathname === "/api/auth/logout") {
      return await logout(req, res);
    }

    if (req.method === "GET" && url.pathname === "/api/auth/me") {
      return await currentUser(req, res);
    }

    if (req.method === "GET" && url.pathname === "/api/admin/me") {
      return await adminMe(req, res);
    }

    return sendError(res, 404, "Route not found.");
  } catch (error) {
    console.error("Server error:", error);

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
}

/* -------------------------------------------------------
   SERVER
------------------------------------------------------- */

const server = http.createServer(handleRequest);

server.listen(PORT, () => {
  console.log(`CoinForest server running on port ${PORT}`);
  console.log("CoinForest database module loaded.");
});
