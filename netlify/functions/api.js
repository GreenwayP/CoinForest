import coinforestHandler from "../../api/index.js";

export default async function handler(event) {
  const requestHeaders = {};

  for (const [key, value] of Object.entries(event.headers || {})) {
    if (value !== undefined) {
      requestHeaders[key] = Array.isArray(value)
        ? value.join(", ")
        : String(value);
    }
  }

  let body = event.body || undefined;

  if (event.isBase64Encoded && body) {
    body = Buffer.from(body, "base64").toString("utf8");
  }

  const req = {
    method: event.httpMethod || "GET",
    url:
      event.rawUrl ||
      `https://${requestHeaders.host || "coinforest.netlify.app"}${event.path || "/"}`,
    headers: requestHeaders,
    body
  };

  let statusCode = 200;
  let responseBody = "";
  const responseHeaders = {};

  const res = {
    headersSent: false,

    setHeader(name, value) {
      responseHeaders[name] = value;
    },

    end(value = "") {
      responseBody = String(value);
      this.headersSent = true;
    }
  };

  Object.defineProperty(res, "statusCode", {
    get() {
      return statusCode;
    },
    set(value) {
      statusCode = value;
    }
  });

  await coinforestHandler(req, res);

  return new Response(responseBody, {
    status: statusCode,
    headers: responseHeaders
  });
}
