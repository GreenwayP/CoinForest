export default function handler(request) {
  return new Response(
    JSON.stringify({
      success: false,
      error: "API route not found."
    }),
    {
      status: 404,
      headers: {
        "Content-Type": "application/json; charset=utf-8"
      }
    }
  );
}
