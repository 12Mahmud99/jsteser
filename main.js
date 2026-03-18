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
const { isValidUrl } = require("./urlValidator");

describe("SSRF URL Validation - Comprehensive Tests", () => {

  test("valid https URL", async () => {
    await expect(isValidUrl("https://example.com")).resolves.toBe(true);
  });

  test("valid http URL", async () => {
    await expect(isValidUrl("http://example.com")).resolves.toBe(true);
  });

  test("valid subdomain", async () => {
    await expect(isValidUrl("https://api.example.com")).resolves.toBe(true);
  });

  test("valid URL with path and query", async () => {
    await expect(isValidUrl("https://example.com/api?x=1")).resolves.toBe(true);
  });

  test("reject localhost", async () => {
    await expect(isValidUrl("http://localhost")).resolves.toBe(false);
  });

  test("reject localhost with port", async () => {
    await expect(isValidUrl("http://localhost:3000")).resolves.toBe(false);
  });

  test("reject 127.0.0.1", async () => {
    await expect(isValidUrl("http://127.0.0.1")).resolves.toBe(false);
  });

  test("reject 0.0.0.0", async () => {
    await expect(isValidUrl("http://0.0.0.0")).resolves.toBe(false);
  });

  test("reject 192.168.x.x", async () => {
    await expect(isValidUrl("http://192.168.1.1")).resolves.toBe(false);
  });

  test("reject 10.x.x.x", async () => {
    await expect(isValidUrl("http://10.0.0.1")).resolves.toBe(false);
  });

  test("reject 172.16.x.x", async () => {
    await expect(isValidUrl("http://172.16.0.1")).resolves.toBe(false);
  });

  test("reject file protocol", async () => {
    await expect(isValidUrl("file:///etc/passwd")).resolves.toBe(false);
  });

  test("reject ftp protocol", async () => {
    await expect(isValidUrl("ftp://example.com")).resolves.toBe(false);
  });

  test("reject gopher protocol", async () => {
    await expect(isValidUrl("gopher://example.com")).resolves.toBe(false);
  });

  test("localhost disguised as subdomain", async () => {
    await expect(isValidUrl("http://localhost.evil.com")).resolves.toBe(true);
  });

  test("reject numeric IP format", async () => {
    await expect(isValidUrl("http://2130706433")).resolves.toBe(false);
  });

  test("reject hex IP", async () => {
    await expect(isValidUrl("http://0x7f000001")).resolves.toBe(false);
  });

  test("reject IPv6 localhost", async () => {
    await expect(isValidUrl("http://[::1]")).resolves.toBe(false);
  });

  test("reject empty string", async () => {
    await expect(isValidUrl("")).resolves.toBe(false);
  });

  test("reject malformed URL", async () => {
    await expect(isValidUrl("not-a-url")).resolves.toBe(false);
  });

  test("reject javascript protocol", async () => {
    await expect(isValidUrl("javascript:alert(1)")).resolves.toBe(false);
  });

  test("@ trick", async () => {
    await expect(isValidUrl("http://127.0.0.1@evil.com")).resolves.toBe(true);
  });

  test("double slash confusion", async () => {
    await expect(isValidUrl("http:////127.0.0.1")).resolves.toBe(false);
  });

});