export type GateRequest = Request<unknown, IncomingRequestCfProperties>;
export type Upstream = (request: GateRequest) => Promise<Response>;

const text = (status: number, body: string) =>
  new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });

export async function handle(
  request: GateRequest,
  upstream: Upstream = (r) => fetch(r),
): Promise<Response> {
  // `cf` and `tlsClientAuth` are absent in local dev; treat that as "no cert".
  const auth: { certPresented?: string; certVerified?: string; certRevoked?: string } =
    request.cf?.tlsClientAuth ?? {};
  const presented = auth.certPresented === "1";
  const verified = auth.certVerified === "SUCCESS";
  const revoked = auth.certRevoked === "1";

  if (presented && verified && !revoked) return upstream(request);

  const status = presented ? 403 : 421;
  const body = presented ? "Client certificate rejected" : "Client certificate required";
  const level = presented ? "warn" : "info";
  const reason = !presented
    ? "no client certificate"
    : revoked
      ? "certificate revoked"
      : `certificate not verified (${auth.certVerified ?? "unknown"})`;
  const url = new URL(request.url);

  console[level](
    JSON.stringify({
      level,
      message: `${status} ${reason} - ${request.method} ${url.hostname}${url.pathname}`,
      action: "reject",
      status,
      host: url.hostname,
      path: url.pathname,
      method: request.method,
      certPresented: auth.certPresented ?? null,
      certVerified: auth.certVerified ?? null,
      certRevoked: auth.certRevoked ?? null,
      httpProtocol: request.cf?.httpProtocol ?? null,
      ray: request.headers.get("cf-ray"),
    }),
  );
  return text(status, body);
}

export default {
  fetch: (request) => handle(request),
} satisfies ExportedHandler;
