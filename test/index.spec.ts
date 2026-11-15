import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { handle, type GateRequest } from "../src/index";

const URL_UNDER_TEST = "https://app.example.com/d/abc?orgId=1";

type TlsAuth = Record<string, string>;

function makeRequest(
  tlsClientAuth?: TlsAuth,
  init: RequestInit = {},
  extraCf: Record<string, unknown> = {},
): GateRequest {
  const cf = tlsClientAuth ? { tlsClientAuth, ...extraCf } : undefined;
  return new Request(URL_UNDER_TEST, { ...init, cf } as RequestInit) as GateRequest;
}

const OK_AUTH: TlsAuth = { certPresented: "1", certVerified: "SUCCESS", certRevoked: "0" };

describe("mtls-gate", () => {
  let log: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    log = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 421 and skips upstream when cf is missing", async () => {
    const upstream = vi.fn();
    const request = makeRequest();
    expect(request.cf).toBeUndefined();

    const response = await handle(request, upstream);

    expect(response.status).toBe(421);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("returns 421 when tlsClientAuth is missing from cf", async () => {
    const upstream = vi.fn();
    const request = new Request(URL_UNDER_TEST, {
      cf: { httpProtocol: "HTTP/2" },
    } as RequestInit) as GateRequest;

    const response = await handle(request, upstream);

    expect(response.status).toBe(421);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("returns 421 with no-store when no cert was presented", async () => {
    const upstream = vi.fn();

    const response = await handle(
      makeRequest({ certPresented: "0", certVerified: "NONE", certRevoked: "0" }),
      upstream,
    );

    expect(response.status).toBe(421);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(await response.text()).toBe("Client certificate required");
    expect(upstream).not.toHaveBeenCalled();
  });

  it("returns 403 when the presented cert fails verification", async () => {
    const upstream = vi.fn();

    const response = await handle(
      makeRequest({
        certPresented: "1",
        certVerified: "FAILED:self signed certificate",
        certRevoked: "0",
      }),
      upstream,
    );

    expect(response.status).toBe(403);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(await response.text()).toBe("Client certificate rejected");
    expect(upstream).not.toHaveBeenCalled();
  });

  it("returns 403 when the presented cert is revoked", async () => {
    const upstream = vi.fn();

    const response = await handle(
      makeRequest({ certPresented: "1", certVerified: "SUCCESS", certRevoked: "1" }),
      upstream,
    );

    expect(response.status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });

  it("passes the same Request to upstream and returns its response unchanged", async () => {
    const upstreamResponse = new Response("origin body", {
      status: 203,
      headers: { "x-origin": "grafana", "content-type": "text/html" },
    });
    const upstream = vi.fn(async () => upstreamResponse);
    const request = makeRequest(OK_AUTH);

    const response = await handle(request, upstream);

    expect(upstream).toHaveBeenCalledTimes(1);
    expect(upstream.mock.calls[0]).toHaveLength(1);
    expect((upstream.mock.calls[0] as unknown[])[0]).toBe(request);
    expect(response).toBe(upstreamResponse);
    expect(response.status).toBe(203);
    expect(response.headers.get("x-origin")).toBe("grafana");
    expect(response.headers.get("content-type")).toBe("text/html");
    expect(response.headers.get("cache-control")).toBeNull();
    expect(await response.text()).toBe("origin body");
  });

  it("delivers a POST body to upstream intact", async () => {
    const payload = JSON.stringify({ query: "up", from: "now-1h" });
    let received: { method: string; contentType: string | null; body: string } | undefined;
    const upstream = vi.fn(async (r: GateRequest) => {
      received = {
        method: r.method,
        contentType: r.headers.get("content-type"),
        body: await r.text(),
      };
      return new Response(null, { status: 204 });
    });

    const response = await handle(
      makeRequest(OK_AUTH, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: payload,
      }),
      upstream,
    );

    expect(response.status).toBe(204);
    expect(received).toEqual({
      method: "POST",
      contentType: "application/json",
      body: payload,
    });
  });

  it("logs exactly one JSON line per rejection, without credentials", async () => {
    const request = makeRequest(
      { certPresented: "0", certVerified: "NONE", certRevoked: "0" },
      {
        method: "POST",
        headers: {
          "cf-ray": "8f1e2d3c4b5a6978-FRA",
          cookie: "grafana_session=super-secret-cookie",
          authorization: "Bearer super-secret-token",
        },
        body: "super-secret-body",
      },
      { httpProtocol: "HTTP/2" },
    );

    await handle(request, vi.fn());

    expect(log).toHaveBeenCalledTimes(1);
    expect(log.mock.calls[0]).toHaveLength(1);
    const line = log.mock.calls[0][0] as string;
    expect(line).not.toContain("\n");
    expect(JSON.parse(line)).toEqual({
      action: "reject",
      status: 421,
      host: "app.example.com",
      path: "/d/abc",
      method: "POST",
      certPresented: "0",
      certVerified: "NONE",
      certRevoked: "0",
      httpProtocol: "HTTP/2",
      ray: "8f1e2d3c4b5a6978-FRA",
    });
    expect(line).not.toContain("super-secret");
    expect(line.toLowerCase()).not.toContain("cookie");
    expect(line.toLowerCase()).not.toContain("authorization");
  });

  it("logs status 403 and null fields when values are absent", async () => {
    await handle(makeRequest({ certPresented: "1" }), vi.fn());

    expect(log).toHaveBeenCalledTimes(1);
    expect(JSON.parse(log.mock.calls[0][0] as string)).toMatchObject({
      action: "reject",
      status: 403,
      certPresented: "1",
      certVerified: null,
      certRevoked: null,
      httpProtocol: null,
      ray: null,
    });
  });

  it("logs nothing for an authorized request", async () => {
    await handle(makeRequest(OK_AUTH), async () => new Response("ok"));

    expect(log).not.toHaveBeenCalled();
  });
});
