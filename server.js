import { neon } from "@neondatabase/serverless";

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error("DATABASE_URL is not configured.");
}

const sql = neon(databaseUrl);

export async function testDatabaseConnection() {
  const result = await sql`SELECT NOW() AS current_time`;
  return result[0];
}

console.log("CoinForest server database module loaded.");
