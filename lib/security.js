import { createHash, randomBytes, timingSafeEqual, randomUUID } from "node:crypto";

export function newSecret(prefix) {
  return prefix + randomBytes(32).toString("base64url");
}

export function newId() {
  return randomUUID();
}

export function hashSecret(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

export function safeEqual(a, b) {
  const left = Buffer.from(String(a ?? ""));
  const right = Buffer.from(String(b ?? ""));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function bearerToken(req) {
  const header = req.headers?.authorization || "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1].trim() : "";
}

export function isSafeToolName(name) {
  return typeof name === "string" &&
    name.length > 0 &&
    name.length <= 96 &&
    /^[a-zA-Z0-9_.-]+$/.test(name);
}

export function jsonSchemaOrEmpty(schema) {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    return { type: "object", properties: {}, additionalProperties: false };
  }
  const serialized = JSON.stringify(schema);
  if (serialized.length > 24_000) {
    return { type: "object", properties: {}, additionalProperties: false };
  }
  return schema;
}
