const dns = require("dns").promises;
const net = require("net");

function isPrivateIP(ip) {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("127.") ||
    ip === "0.0.0.0"
  );
}

async function isValidUrl(url) {
  try {
    const parsed = new URL(url);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return false;
    }

    const hostname = parsed.hostname;

    if (hostname === "localhost") return false;

    const { address } = await dns.lookup(hostname);

    if (isPrivateIP(address)) {
      return false;
    }

    return true;

  } catch (err) {
    return false;
  }
}

module.exports = { isValidUrl };

const { isValidUrl } = require("./urlValidator");

describe("SSRF URL Validation", () => {

  test("valid public URL", async () => {
    await expect(isValidUrl("https://example.com")).resolves.toBe(true);
  });

  test("reject localhost", async () => {
    await expect(isValidUrl("http://localhost:3000")).resolves.toBe(false);
  });

  test("reject 127.0.0.1", async () => {
    await expect(isValidUrl("http://127.0.0.1")).resolves.toBe(false);
  });

  test("reject internal IP", async () => {
    await expect(isValidUrl("http://192.168.1.1")).resolves.toBe(false);
  });

  test("reject file protocol", async () => {
    await expect(isValidUrl("file:///etc/passwd")).resolves.toBe(false);
  });

});