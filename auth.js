export function requireAuth(request) {
  const jwt = request.headers.get("cf-access-jwt-assertion");
  if (!jwt) {
    throw new Error("Unauthorized");
  }
  return jwt;
}

export async function getUserContext(jwt) {
  const payload = JSON.parse(
    atob(jwt.split(".")[1])
  );

  const email = payload.email?.toLowerCase();
  if (!email) throw new Error("Email missing from Access token");

  return {
    email,
    role: email.endsWith("@ussignal.com") ? "admin" : "customer"
  };
}
