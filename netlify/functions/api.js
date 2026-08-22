import coinforestHandler from "../../api/index.js";

export const config = {
  path: "/api/*"
};

export default async function handler(request) {
  const url = new URL(request.url);

  const headers = {};

  request.headers.forEach((value, key) => {
    headers[key] = value;
  });

  let body;

  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.text();
  }

  const req = {
    method: request.method,
    url: url.toString(),
    headers,
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
