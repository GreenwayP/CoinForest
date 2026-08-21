import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { neon } from "@neondatabase/serverless";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sql = neon(process.env.DATABASE_URL);
const PORT = process.env.PORT || 3000;

const mime = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon"
};

function json(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
  });

  res.end(JSON.stringify(data));
}

function serveFile(res, file) {
  if (!fs.existsSync(file)) {
    return json(res, 404, {
      success: false,
      error: "Page not found."
    });
  }

  const ext = path.extname(file);

  res.writeHead(200, {
    "Content-Type": mime[ext] || "application/octet-stream"
  });

  fs.createReadStream(file).pipe(res);
}

async function handle(req, res) {
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
    });
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);

  /* WEBSITE */

  if (req.method === "GET" && url.pathname === "/") {
    return serveFile(res, path.join(__dirname, "index.html"));
  }

  if (req.method === "GET") {
    const clean = url.pathname.replace(/^\/+/, "");

    if (
      clean === "index.html" ||
      clean === "dashboard.html" ||
      clean === "login.html" ||
      clean === "wallet.html"
    ) {
      return serveFile(res, path.join(__dirname, clean));
    }
  }

  /* DATABASE TEST */

  if (req.method === "GET" && url.pathname === "/api/health") {
    try {
      const result = await sql`SELECT NOW() AS current_time`;

      return json(res, 200, {
        success: true,
        database: "connected",
        current_time: result[0].current_time
      });
    } catch (error) {
      console.error(error);

      return json(res, 500, {
        success: false,
        error: "Database connection failed."
      });
    }
  }

  return json(res, 404, {
    success: false,
    error: "Route not found."
  });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(error => {
    console.error(error);

    json(res, 500, {
      success: false,
      error: "Internal server error."
    });
  });
});

server.listen(PORT, () => {
  console.log(`CoinForest running on port ${PORT}`);
});
