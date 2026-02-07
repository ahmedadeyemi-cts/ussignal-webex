export function normalizeOrgName(name) {
  return name
    .toLowerCase()
    .replace(/city of |town of |county of /gi, "")
    .replace(/[^a-z0-9]/g, "")
    .trim();
}
