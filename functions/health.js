export async function onRequest() {
  return new Response(
    JSON.stringify({
      status: "PAGES_FUNCTION_OK"
    }),
    {
      headers: { "content-type": "application/json" }
    }
  );
}
