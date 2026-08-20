import http from "node:http";
import crypto from "node:crypto";
import { neon } from "@neondatabase/serverless";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error("DATABASE_URL is not configured.");
}

const sql = neon(databaseUrl);
const PORT = process.env.PORT || 3000;

/* =====================================================
   RESPONSE HELPERS
===================================================== */

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, OPTIONS"
  };
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    ...corsHeaders(),
    "Content-Type": "application/json; charset=utf-8"
  });

  res.end(JSON.stringify(data));
}

function sendError(res, statusCode, message) {
  return sendJson(res, statusCode, {
    success: false,
    error: message
  });
}

/* =====================================================
   BODY
===================================================== */

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

/* =====================================================
   CRYPTO
===================================================== */

function generateToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

/*
  Password hashing using scrypt.
  The stored value contains the salt and parameters.
*/

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");

    crypto.scrypt(
      password,
      salt,
      64,
      {
        N: 16384,
        r: 8,
        p: 1
      },
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(
          `scrypt$16384$8$1$${salt}$${derivedKey.toString("hex")}`
        );
      }
    );
  });
}

function verifyPassword(password, storedHash) {
  return new Promise(resolve => {
    try {
      const parts = storedHash.split("$");

      if (parts.length !== 6 || parts[0] !== "scrypt") {
        resolve(false);
        return;
      }

      const N = Number(parts[1]);
      const r = Number(parts[2]);
      const p = Number(parts[3]);
      const salt = parts[4];
      const storedKey = Buffer.from(parts[5], "hex");

      crypto.scrypt(
        password,
        salt,
        storedKey.length,
        { N, r, p },
        (error, derivedKey) => {
          if (error) {
            resolve(false);
            return;
          }

          if (derivedKey.length !== storedKey.length) {
            resolve(false);
            return;
          }

          resolve(
            crypto.timingSafeEqual(
              derivedKey,
              storedKey
            )
          );
        }
      );
    } catch {
      resolve(false);
    }
  });
}

/* =====================================================
   VALIDATION
===================================================== */

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6
  );
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim();
}

/* =====================================================
   DATABASE HEALTH
===================================================== */

async function testDatabaseConnection() {
  const result = await sql`
    SELECT NOW() AS current_time
  `;

  return result[0];
}

/* =====================================================
   SESSION
===================================================== */

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

/* =====================================================
   REGISTER
===================================================== */

async function register(req, res) {
  const body = await readBody(req);

  const firstName = String(body.first_name || "").trim();
  const lastName = String(body.last_name || "").trim();
  const username = String(body.username || "").trim();
  const email = normalizeEmail(body.email);
  const password = body.password;

  if (!firstName) {
    return sendError(res, 400, "First name is required.");
  }

  if (!lastName) {
    return sendError(res, 400, "Last name is required.");
  }

  if (!username) {
    return sendError(res, 400, "Username is required.");
  }

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

  const existingEmail = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(email) = ${email}
    LIMIT 1
  `;

  if (existingEmail.length > 0) {
    return sendError(
      res,
      409,
      "An account with this email already exists."
    );
  }

  const existingUsername = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(username) = LOWER(${username})
    LIMIT 1
  `;

  if (existingUsername.length > 0) {
    return sendError(
      res,
      409,
      "That username is already in use."
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
      ${userId},
      ${passwordHash},
      NOW(),
      0,
      NOW(),
      NOW()
    )
  `;

  return sendJson(res, 201, {
    success: true,
    message: "Account created successfully.",
    user: {
      id: userId,
      email,
      first_name: firstName,
      last_name: lastName,
      username,
      role: "user",
      kyc_status: "not_verified"
    }
  });
}

/* =====================================================
   LOGIN
===================================================== */

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
      p.last_name,
      p.username,
      p.status,
      p.kyc_status,
      r.name AS role,
      c.password_hash,
      c.failed_login_attempts,
      c.locked_until
    FROM profiles p
    INNER JOIN roles r
      ON r.id = p.role_id
    INNER JOIN auth_credentials c
      ON c.user_id = p.id
    WHERE LOWER(p.email) = ${email}
    LIMIT 1
  `;

  if (result.length === 0) {
    return sendError(
      res,
      401,
      "Invalid email or password."
    );
  }

  const user = result[0];

  if (user.status !== "active") {
    return sendError(
      res,
      403,
      "This account is not active."
    );
  }

  if (
    user.locked_until &&
    new Date(user.locked_until) > new Date()
  ) {
    return sendError(
      res,
      423,
      "This account is temporarily locked. Please try again later."
    );
  }

  const passwordCorrect = await verifyPassword(
    password,
    user.password_hash
  );

  if (!passwordCorrect) {

    const attempts =
      Number(user.failed_login_attempts || 0) + 1;

    if (attempts >= 5) {

      await sql`
        UPDATE auth_credentials
        SET
          failed_login_attempts = 0,
          locked_until = NOW() + INTERVAL '15 minutes',
          updated_at = NOW()
        WHERE user_id = ${user.id}
      `;

      return sendError(
        res,
        423,
        "Too many failed login attempts. Account temporarily locked."
      );
    }

    await sql`
      UPDATE auth_credentials
      SET
        failed_login_attempts = ${attempts},
        updated_at = NOW()
      WHERE user_id = ${user.id}
    `;

    return sendError(
      res,
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

  const token = await createSession(user.id);

  return sendJson(res, 200, {
    success: true,
    message: "Login successful.",
    token,
    user: {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      role: user.role,
      status: user.status,
      kyc_status: user.kyc_status
    }
  });
}

/* =====================================================
   LOGOUT
===================================================== */

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

/* =====================================================
   CURRENT USER
===================================================== */

async function currentUser(req, res) {
  const user = await getAuthenticatedUser(req);

  if (!user) {
    return sendError(
      res,
      401,
      "Authentication required."
    );
  }

  return sendJson(res, 200, {
    success: true,
    user
  });
}

/* =====================================================
   ADMIN
===================================================== */

async function adminMe(req, res) {
  const user = await getAuthenticatedUser(req);

  if (!user) {
    return sendError(
      res,
      401,
      "Authentication required."
    );
  }

  if (user.role !== "admin") {
    return sendError(
      res,
      403,
      "Administrator access required."
    );
  }

  return sendJson(res, 200, {
    success: true,
    user
  });
}

/* =====================================================
   ROUTER
===================================================== */

async function handleRequest(req, res) {

  if (req.method === "OPTIONS") {
    res.writeHead(204, corsHeaders());
    res.end();
    return;
  }

  const url = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  try {

    if (
      req.method === "GET" &&
      url.pathname === "/api/health"
    ) {
      const result =
        await testDatabaseConnection();

      return sendJson(res, 200, {
        success: true,
        database: "connected",
        current_time: result.current_time
      });
    }

    if (
      req.method === "POST" &&
      url.pathname === "/api/auth/register"
    ) {
      return await register(req, res);
    }

    if (
      req.method === "POST" &&
      url.pathname === "/api/auth/login"
    ) {
      return await login(req, res);
    }

    if (
      req.method === "POST" &&
      url.pathname === "/api/auth/logout"
    ) {
      return await logout(req, res);
    }

    if (
      req.method === "GET" &&
      url.pathname === "/api/auth/me"
    ) {
      return await currentUser(req, res);
    }

    if (
      req.method === "GET" &&
      url.pathname === "/api/admin/me"
    ) {
      return await adminMe(req, res);
    }

    return sendError(
      res,
      404,
      "Route not found."
    );

  } catch (error) {

    console.error("Server error:", error);

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
}

/* =====================================================
   SERVER
===================================================== */

const server = http.createServer(handleRequest);

server.listen(PORT, () => {
  console.log(
    `CoinForest server running on port ${PORT}`
  );
});
