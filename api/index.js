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

function hash(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(48).toString("hex");
}

function bearer(request) {
  const value = request.headers.get("authorization") || "";

  if (!value.startsWith("Bearer ")) {
    return null;
  }

  return value.slice(7).trim();
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getBaseUrl(request) {
  const forwardedHost =
    request.headers.get("x-forwarded-host");

  const host =
    forwardedHost ||
    request.headers.get("host");

  const protocol =
    request.headers.get("x-forwarded-proto") ||
    "https";

  if (host) {
    return `${protocol}://${host}`;
  }

  return new URL(request.url).origin;
}


/* =====================================================
   RESEND EMAIL
===================================================== */

async function sendEmail({ to, subject, html, text }) {

  const apiKey = process.env.RESEND_API_KEY;

  if (!apiKey) {
    throw new Error(
      "RESEND_API_KEY is not configured."
    );
  }

  /*
    IMPORTANT:

    onboarding@resend.dev is Resend's onboarding/test
    sender. It is being used because CoinForest does not
    currently have a verified sending domain.

    After a CoinForest domain is verified in Resend,
    replace this with something such as:

    CoinForest <no-reply@yourverifieddomain.com>
  */

  const result = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },

      body: JSON.stringify({
        from: "CoinForest <onboarding@resend.dev>",
        to: [to],
        subject,
        html,
        text
      })
    }
  );

  const data = await result.json();

  if (!result.ok) {
    console.error(
      "Resend error:",
      data
    );

    throw new Error(
      data.message ||
      data.error ||
      "Unable to send email."
    );
  }

  return data;
}


/* =====================================================
   CREATE EMAIL TOKEN
===================================================== */

async function createEmailToken(
  userId,
  tokenType,
  expiresMinutes = 30
) {

  /*
    Remove older unused tokens of the same type.
  */

  await sql`
    DELETE FROM auth_email_tokens
    WHERE user_id = ${userId}
      AND token_type = ${tokenType}
      AND used_at IS NULL
  `;

  const token = createToken();

  const tokenHash = hash(token);

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

  return token;
}


/* =====================================================
   SEND VERIFICATION EMAIL
===================================================== */

async function sendVerificationEmail(
  request,
  user
) {

  const token = await createEmailToken(
    user.id,
    "email_verification",
    60
  );

  const baseUrl =
    getBaseUrl(request);

  const link =
    `${baseUrl}/verify-email.html?token=${encodeURIComponent(token)}`;

  const name =
    escapeHtml(
      user.full_name ||
      user.username ||
      "there"
    );

  const html = `
<!DOCTYPE html>
<html>
<body style="
  margin:0;
  padding:0;
  background:#f4f7fa;
  font-family:Arial,Helvetica,sans-serif;
">

<div style="
  max-width:600px;
  margin:40px auto;
  background:#ffffff;
  border-radius:18px;
  padding:40px;
  box-shadow:0 10px 30px rgba(0,0,0,.08);
">

  <h1 style="
    margin:0 0 20px;
    color:#10233a;
  ">
    Welcome to <span style="color:#2ecc71;">CoinForest</span>
  </h1>

  <p style="
    color:#536273;
    line-height:1.7;
  ">
    Hello ${name},
  </p>

  <p style="
    color:#536273;
    line-height:1.7;
  ">
    Your CoinForest account has been created.
    Please confirm your email address to activate
    your account.
  </p>

  <p style="margin:30px 0;">

    <a
      href="${link}"
      style="
        display:inline-block;
        background:#2ecc71;
        color:#06140c;
        text-decoration:none;
        font-weight:700;
        padding:14px 24px;
        border-radius:10px;
      "
    >
      Confirm Email Address
    </a>

  </p>

  <p style="
    color:#718096;
    font-size:13px;
    line-height:1.6;
  ">
    This confirmation link expires in 60 minutes.
  </p>

  <p style="
    color:#9aa6b2;
    font-size:12px;
    line-height:1.6;
  ">
    If you did not create this account, you can safely
    ignore this email.
  </p>

</div>

</body>
</html>
`;

  const text = `
Welcome to CoinForest.

Hello ${user.full_name || user.username || "there"},

Please confirm your CoinForest email address:

${link}

This confirmation link expires in 60 minutes.

If you did not create this account, you can ignore this email.
`;

  return await sendEmail({
    to: user.email,
    subject: "Confirm your CoinForest account",
    html,
    text
  });
}


/* =====================================================
   SEND PASSWORD RESET EMAIL
===================================================== */

async function sendPasswordResetEmail(
  request,
  user
) {

  const token = await createEmailToken(
    user.id,
    "password_reset",
    30
  );

  const baseUrl =
    getBaseUrl(request);

  const link =
    `${baseUrl}/reset-password.html?token=${encodeURIComponent(token)}`;

  const name =
    escapeHtml(
      user.full_name ||
      user.username ||
      "there"
    );

  const html = `
<!DOCTYPE html>
<html>
<body style="
  margin:0;
  padding:0;
  background:#f4f7fa;
  font-family:Arial,Helvetica,sans-serif;
">

<div style="
  max-width:600px;
  margin:40px auto;
  background:#ffffff;
  border-radius:18px;
  padding:40px;
  box-shadow:0 10px 30px rgba(0,0,0,.08);
">

  <h1 style="
    margin:0 0 20px;
    color:#10233a;
  ">
    Coin<span style="color:#2ecc71;">Forest</span>
  </h1>

  <p style="
    color:#536273;
    line-height:1.7;
  ">
    Hello ${name},
  </p>

  <p style="
    color:#536273;
    line-height:1.7;
  ">
    We received a request to reset the password
    for your CoinForest account.
  </p>

  <p style="margin:30px 0;">

    <a
      href="${link}"
      style="
        display:inline-block;
        background:#2ecc71;
        color:#06140c;
        text-decoration:none;
        font-weight:700;
        padding:14px 24px;
        border-radius:10px;
      "
    >
      Reset Password
    </a>

  </p>

  <p style="
    color:#718096;
    font-size:13px;
    line-height:1.6;
  ">
    This password-reset link expires in 30 minutes
    and can only be used once.
  </p>

  <p style="
    color:#9aa6b2;
    font-size:12px;
    line-height:1.6;
  ">
    If you did not request a password reset, you can
    safely ignore this email.
  </p>

</div>

</body>
</html>
`;

  const text = `
CoinForest password reset.

Hello ${user.full_name || user.username || "there"},

Reset your CoinForest password here:

${link}

This link expires in 30 minutes and can only be used once.

If you did not request this reset, you can ignore this email.
`;

  return await sendEmail({
    to: user.email,
    subject: "Reset your CoinForest password",
    html,
    text
  });
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
    String(body.first_name || "").trim();

  const lastName =
    String(body.last_name || "").trim();

  const username =
    String(body.username || "").trim();


  if (!e || !password) {
    return response(400, {
      success:false,
      error:"Email and password are required."
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
      error:"Password must contain at least 6 characters."
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
      error:"An account with this email already exists."
    });
  }


  const existingUsername =
    await sql`
      SELECT id
      FROM profiles
      WHERE LOWER(username) = LOWER(${username})
      LIMIT 1
    `;

  if (existingUsername.length > 0) {
    return response(409, {
      success:false,
      error:"That username is already in use."
    });
  }


  const id =
    crypto.randomUUID();


  const fullName =
    [firstName, lastName]
      .filter(Boolean)
      .join(" ");


  try {

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
        ${hash(password)},
        NOW(),
        0,
        NOW(),
        NOW()
      )
    `;


    const user = {
      id,
      email:e,
      first_name:firstName,
      last_name:lastName,
      username,
      full_name:fullName,
      role:"user"
    };


    await sendVerificationEmail(
      request,
      user
    );


    return response(201, {
      success:true,
      message:
        "Account created. Please check your email to confirm your account.",
      email_sent:true,
      user
    });


  } catch (error) {

    console.error(
      "Registration/email error:",
      error
    );


    /*
      If email sending fails after account creation,
      remove the newly created account so we don't leave
      an unusable unverified account behind.
    */

    try {

      await sql`
        DELETE FROM auth_credentials
        WHERE user_id = ${id}
      `;

      await sql`
        DELETE FROM profiles
        WHERE id = ${id}
      `;

    } catch (cleanupError) {

      console.error(
        "Registration cleanup error:",
        cleanupError
      );

    }


    return response(500, {
      success:false,
      error:
        "We could not send the confirmation email. Please try again."
    });
  }
}


/* =====================================================
   VERIFY EMAIL
===================================================== */

async function verifyEmail(request) {

  const url =
    new URL(request.url);

  const token =
    url.searchParams.get("token");


  if (!token) {
    return response(400, {
      success:false,
      error:"Verification token is required."
    });
  }


  const tokenHash =
    hash(token);


  const result =
    await sql`
      SELECT
        t.id,
        t.user_id,
        t.expires_at,
        p.email_verified_at
      FROM auth_email_tokens t
      INNER JOIN profiles p
        ON p.id = t.user_id
      WHERE t.token_hash = ${tokenHash}
        AND t.token_type = 'email_verification'
        AND t.used_at IS NULL
      LIMIT 1
    `;


  if (result.length === 0) {
    return response(400, {
      success:false,
      error:"This verification link is invalid or has already been used."
    });
  }


  const tokenRow =
    result[0];


  if (
    new Date(tokenRow.expires_at) <=
    new Date()
  ) {

    return response(410, {
      success:false,
      error:"This verification link has expired. Please request a new one."
    });

  }


  await sql`
    UPDATE profiles
    SET
      email_verified_at = NOW(),
      updated_at = NOW()
    WHERE id = ${tokenRow.user_id}
  `;


  await sql`
    UPDATE auth_email_tokens
    SET used_at = NOW()
    WHERE id = ${tokenRow.id}
  `;


  return response(200, {
    success:true,
    message:"Email verified successfully."
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
        username,
        email_verified_at
      FROM profiles
      WHERE LOWER(email) = ${e}
      LIMIT 1
    `;


  /*
    Don't reveal whether the account exists.
  */

  if (result.length === 0) {
    return response(200, {
      success:true,
      message:
        "If an account exists for that email, a verification email has been sent."
    });
  }


  const user =
    result[0];


  if (user.email_verified_at) {
    return response(200, {
      success:true,
      message:"This email address is already verified."
    });
  }


  try {

    await sendVerificationEmail(
      request,
      user
    );

    return response(200, {
      success:true,
      message:
        "A new verification email has been sent."
    });

  } catch (error) {

    console.error(
      "Resend verification error:",
      error
    );

    return response(500, {
      success:false,
      error:
        "Unable to send the verification email right now."
    });
  }
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
      error:"Email and password are required."
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
      error:"Invalid email or password."
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
    hash(password) !==
    user.password_hash
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
        failed_login_attempts = ${attempts},
        updated_at = NOW()
      WHERE user_id = ${user.id}
    `;


    return response(401, {
      success:false,
      error:"Invalid email or password."
    });
  }


  /*
    Email confirmation is required before login.
  */

  if (!user.email_verified_at) {

    return response(403, {
      success:false,
      error:
        "Please confirm your email address before signing in.",
      email_verification_required:true
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
      ${hash(token)},
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
      role:user.role
    }
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
        full_name,
        username
      FROM profiles
      WHERE LOWER(email) = ${e}
      LIMIT 1
    `;


  /*
    Always return the same message whether or not
    the account exists.
  */

  if (result.length === 0) {

    return response(200, {
      success:true,
      message:
        "If an account exists for that email, a password reset email has been sent."
    });

  }


  const user =
    result[0];


  try {

    await sendPasswordResetEmail(
      request,
      user
    );


    return response(200, {
      success:true,
      message:
        "If an account exists for that email, a password reset email has been sent."
    });

  } catch (error) {

    console.error(
      "Password reset email error:",
      error
    );

    return response(500, {
      success:false,
      error:
        "Unable to send the password reset email right now."
    });
  }
}


/* =====================================================
   RESET PASSWORD
===================================================== */

async function resetPassword(body) {

  const token =
    String(body.token || "").trim();

  const newPassword =
    String(body.password || "");


  if (!token) {
    return response(400, {
      success:false,
      error:"Reset token is required."
    });
  }


  if (newPassword.length < 6) {
    return response(400, {
      success:false,
      error:
        "Password must contain at least 6 characters."
    });
  }


  const tokenHash =
    hash(token);


  const result =
    await sql`
      SELECT
        id,
        user_id,
        expires_at
      FROM auth_email_tokens
      WHERE token_hash = ${tokenHash}
        AND token_type = 'password_reset'
        AND used_at IS NULL
      LIMIT 1
    `;


  if (result.length === 0) {

    return response(400, {
      success:false,
      error:
        "This password reset link is invalid or has already been used."
    });

  }


  const tokenRow =
    result[0];


  if (
    new Date(tokenRow.expires_at) <=
    new Date()
  ) {

    return response(410, {
      success:false,
      error:
        "This password reset link has expired. Please request another one."
    });

  }


  await sql`
    UPDATE auth_credentials
    SET
      password_hash = ${hash(newPassword)},
      password_updated_at = NOW(),
      failed_login_attempts = 0,
      locked_until = NULL,
      updated_at = NOW()
    WHERE user_id = ${tokenRow.user_id}
  `;


  await sql`
    UPDATE auth_email_tokens
    SET used_at = NOW()
    WHERE id = ${tokenRow.id}
  `;


  /*
    Revoke all existing sessions after a password reset.
    The customer will need to sign in again.
  */

  await sql`
    UPDATE user_sessions
    SET
      status = 'revoked',
      revoked_at = NOW(),
      updated_at = NOW()
    WHERE user_id = ${tokenRow.user_id}
      AND status = 'active'
  `;


  return response(200, {
    success:true,
    message:
      "Password reset successfully. You can now sign in."
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
    hash(token);


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
      WHERE s.session_token_hash = ${tokenHash}
        AND s.status = 'active'
        AND s.expires_at > NOW()
      LIMIT 1
    `;


  if (result.length === 0) {
    return response(401, {
      success:false,
      error:"Invalid or expired session."
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
      WHERE session_token_hash = ${hash(token)}
        AND status = 'active'
    `;

  }


  return response(200, {
    success:true,
    message:"Logged out successfully."
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
      request.method === "GET" &&
      path === "/api/auth/verify-email"
    ) {

      return await verifyEmail(
        request
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
      path === "/api/auth/login"
    ) {

      const body =
        await request.json();

      return await login(
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

      return await resetPassword(
        body
      );

    }


    if (
      request.method === "POST" &&
      path === "/api/auth/logout"
    ) {

      return await logout(
        request
      );

    }


    if (
      request.method === "GET" &&
      path === "/api/auth/me"
    ) {

      return await me(
        request
      );

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
      error:"Internal server error."
    });

  }

}
