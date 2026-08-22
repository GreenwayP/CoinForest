import coinforestHandler from "../../api/index.js";

export default async function handler(event) {
  const headers = {};

  for (const [key, value] of Object.entries(event.headers || {})) {
    headers[key] = Array.isArray(value)
      ? value.join(", ")
      : String(value);
  }

  const req = {
    method: event.httpMethod || "GET",
    url: event.rawUrl || event.path || "/",
    headers,
    body: event.body || undefined
  };

  let responseBody = "";
  const responseHeaders = {};
  let statusCode = 200;

  const res = {
    headersSent: false,

    setHeader(name, value) {
      responseHeaders[name] = value;
    },

    end(body = "") {
      responseBody = body;
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

  return {
    statusCode,
    headers: responseHeaders,
    body: responseBody
  };
}
