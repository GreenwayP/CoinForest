import http from "node:http";
import crypto from "node:crypto";
import { neon } from "@neondatabase/serverless";

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is not configured.");
}

const sql = neon(DATABASE_URL);
const PORT = process.env.PORT || 3000;
const SESSION_DAYS = 30;

/* =====================================================
   RESPONSE
===================================================== */

function headers() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Content-Type": "application/json; charset=utf-8"
  };
}

function json(res, status, data) {
  res.writeHead(status, headers());
  res.end(JSON.stringify(data));
}

function error(res, status, message) {
  return json(res, status, {
    success: false,
    error: message
  });
}

/* =====================================================
   REQUEST BODY
===================================================== */

function readBody(req) {
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
      if (!body.trim()) {
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
   SECURITY
===================================================== */

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function clean(value) {
  if (value === undefined || value === null) return null;

  const result = String(value).trim();

  return result || null;
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
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

function getToken(req) {
  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return null;
  }

  return authorization.substring(7).trim() || null;
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6 &&
    password.length <= 200
  );
}

/* =====================================================
   DATABASE HEALTH
===================================================== */

async function databaseHealth(req, res) {
  try {
    const result = await sql`
      SELECT NOW() AS current_time
    `;

    return json(res, 200, {
      success: true,
      database: "connected",
      current_time: result[0].current_time
    });
  } catch (err) {
    console.error(err);

    return error(
      res,
      500,
      "Database connection failed."
    );
  }
}

/* =====================================================
   CREATE SESSION
===================================================== */

async function createSession(userId, req) {
  const token = generateToken();
  const tokenHash = hashToken(token);

  const userAgent = req.headers["user-agent"]
    ? String(req.headers["user-agent"]).slice(0, 1000)
    : null;

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
      NULL,
      ${userAgent},
      NULL,
      'active',
      NOW(),
      NOW() + (${SESSION_DAYS} || ' days')::interval,
      NOW(),
      NOW()
    )
  `;

  return token;
}

/* =====================================================
   AUTHENTICATED USER
===================================================== */

async function getUser(req) {
  const token = getToken(req);

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
    JOIN profiles p
      ON p.id = s.user_id
    JOIN roles r
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

  const email = normalizeEmail(body.email);
  const password = body.password;

  const firstName = clean(body.first_name);
  const lastName = clean(body.last_name);
  const username = clean(body.username);

  if (!email) {
    return error(res, 400, "Email is required.");
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return error(res, 400, "Enter a valid email address.");
  }

  if (!validPassword(password)) {
    return error(
      res,
      400,
      "Password must contain at least 6 characters."
    );
  }

  if (!username) {
    return error(res, 400, "Username is required.");
  }

  const existingEmail = await sql`
    SELECT id
    FROM profiles
    WHERE LOWER(email) = ${email}
    LIMIT 1
  `;

  if (existingEmail.length) {
    return error(
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

  if (existingUsername.length) {
    return error(
      res,
      409,
      "That username is already in use."
    );
  }

  const role = await sql`
    SELECT id
    FROM roles
    WHERE name = 'user'
    LIMIT 1
  `;

  if (!role.length) {
    return error(
      res,
      500,
      "User role is not configured."
    );
  }

  const userId = crypto.randomUUID();
  const passwordHash = hashPassword(password);

  /*
   * Create profile.
   */
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
      ${role[0].id},
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
   * Create password credentials.
   */
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

  return json(res, 201, {
    success: true,
    message: "Account created successfully.",
    user: {
      id: userId,
      email,
      first_name: firstName,
      last_name: lastName,
      username,
      role: "user",
      status: "active",
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
    return error(
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
      p.two_factor_enabled,
      r.name AS role,
      c.password_hash,
      c.failed_login_attempts,
      c.locked_until
    FROM profiles p
    JOIN roles r
      ON r.id = p.role_id
    JOIN auth_credentials c
      ON c.user_id = p.id
    WHERE LOWER(p.email) = ${email}
    LIMIT 1
  `;

  if (!result.length) {
    return error(
      res,
      401,
      "Invalid email or password."
    );
  }

  const account = result[0];

  if (account.status !== "active") {
    return error(
      res,
      403,
      "This account is not active."
    );
  }

  if (
    account.locked_until &&
    new Date(account.locked_until).getTime() > Date.now()
  ) {
    return error(
      res,
      423,
      "Account temporarily locked. Please try again later."
    );
  }

  const passwordHash = hashPassword(password);

  if (passwordHash !== account.password_hash) {
    const attempts =
      Number(account.failed_login_attempts || 0) + 1;

    if (attempts >= 5) {
      await sql`
        UPDATE auth_credentials
        SET
          failed_login_attempts = 0,
          locked_until = NOW() + INTERVAL '15 minutes',
          updated_at = NOW()
        WHERE user_id = ${account.id}
      `;

      return error(
        res,
        423,
        "Too many failed attempts. Account locked for 15 minutes."
      );
    }

    await sql`
      UPDATE auth_credentials
      SET
        failed_login_attempts = ${attempts},
        updated_at = NOW()
      WHERE user_id = ${account.id}
    `;

    return error(
      res,
      401,
      "Invalid email or password."
    );
  }

  /*
   * Successful login.
   */
  await sql`
    UPDATE auth_credentials
    SET
      failed_login_attempts = 0,
      locked_until = NULL,
      updated_at = NOW()
    WHERE user_id = ${account.id}
  `;

  const token = await createSession(
    account.id,
    req
  );

  return json(res, 200, {
    success: true,
    message: "Login successful.",
    token,
    user: {
      id: account.id,
      email: account.email,
      first_name: account.first_name,
      last_name: account.last_name,
      username: account.username,
      role: account.role,
      status: account.status,
      kyc_status: account.kyc_status,
      two_factor_enabled: account.two_factor_enabled
    }
  });
}

/* =====================================================
   LOGOUT
===================================================== */

async function logout(req, res) {
  const token = getToken(req);

  if (!token) {
    return json(res, 200, {
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

  return json(res, 200, {
    success: true,
    message: "Logged out successfully."
  });
}

/* =====================================================
   CURRENT USER
===================================================== */

async function currentUser(req, res) {
  const user = await getUser(req);

  if (!user) {
    return error(
      res,
      401,
      "Authentication required."
    );
  }

  return json(res, 200, {
    success: true,
    user
  });
}

/* =====================================================
   ADMIN
===================================================== */

async function adminMe(req, res) {
  const user = await getUser(req);

  if (!user) {
    return error(
      res,
      401,
      "Authentication required."
    );
  }

  if (user.role !== "admin") {
    return error(
      res,
      403,
      "Administrator access required."
    );
  }

  return json(res, 200, {
    success: true,
    user
  });
}

/* =====================================================
   ROUTER
===================================================== */

async function handleRequest(req, res) {
  if (req.method === "OPTIONS") {
    res.writeHead(204, headers());
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
      return await databaseHealth(req, res);
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

    return error(res, 404, "Route not found.");

  } catch (err) {
    console.error("CoinForest server error:", err);

    return error(
      res,
      500,
      "Internal server error."
    );
  }
}

/* =====================================================
   START
===================================================== */

const server = http.createServer(handleRequest);

server.listen(PORT, () => {
  console.log(
    `CoinForest server running on port ${PORT}`
  );
});
