import { createHmac, timingSafeEqual } from "node:crypto";

const MAX_SKEW_SECONDS = 300;

function safeEqualHex(a: string, b: string): boolean {
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b)) return false;
  const aa = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (aa.length !== bb.length) return false;
  return timingSafeEqual(aa, bb);
}

export function verifySignedRequest(
  request: Request,
  target = "",
  snapshotId = ""
): boolean {
  const secret = process.env.BROWSER_BRIDGE_SECRET || "";
  const timestamp = request.headers.get("x-mind-timestamp") || "";
  const supplied = request.headers.get("x-mind-signature") || "";
  if (!secret || !timestamp || !supplied) return false;

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) return false;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > MAX_SKEW_SECONDS) return false;

  const pathname = new URL(request.url).pathname;
  const payload = [timestamp, pathname, target, snapshotId].join("\n");
  const expected = createHmac("sha256", secret).update(payload).digest("hex");
  return safeEqualHex(supplied, expected);
}
