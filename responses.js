export const jsonHeaders = {
  "content-type": "application/json",
  "cache-control": "no-store",
};

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...jsonHeaders, ...extraHeaders },
  });
}

export function text(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { "cache-control": "no-store", ...headers },
  });
}

export function err(status, code, message, extra = {}) {
  return json({ ok: false, error: code, message, ...extra }, status);
}
