import coinforestHandler from "../../api/index.js";

export default async function handler(event) {
  const headers = new Headers();

  for (const [key, value] of Object.entries(event.headers || {})) {
    if (value !== undefined) {
      headers.set(
        key,
        Array.isArray(value) ? value.join(", ") : String(value)
      );
    }
  }

  const request = new Request(
    event.rawUrl || `https://${event.headers?.host || "coinforest.netlify.app"}${event.path || "/"}`,
    {
      method: event.httpMethod || "GET",
      headers,
      body:
        event.httpMethod !== "GET" &&
        event.httpMethod !== "HEAD"
          ? event.body || undefined
          : undefined
    }
  );

  const response = await coinforestHandler(request);

  return response;
}
