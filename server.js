import http from "node:http";
import coinforestHandler from "./api/index.js";

const PORT = process.env.PORT || 10000;

const server = http.createServer(async (req, res) => {
  try {
    const chunks = [];

    for await (const chunk of req) {
      chunks.push(chunk);
    }

    if (chunks.length > 0) {
      req.body = Buffer.concat(chunks).toString();
    } else {
      req.body = undefined;
    }

    await coinforestHandler(req, res);

  } catch (error) {
    console.error("CoinForest server error:", error);

    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader(
        "Content-Type",
        "application/json"
      );

      res.end(
        JSON.stringify({
          success: false,
          error: "Internal server error."
        })
      );
    }
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `CoinForest server running on port ${PORT}`
  );
});
