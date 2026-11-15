# cloudflare-mtls-worker

A Cloudflare Worker that enforces mTLS on the hostnames routed to it in [wrangler.jsonc](wrangler.jsonc).

A browser reuses an open connection to one of your sites for your other sites. If that connection was opened to an unprotected site, it carries no client certificate, so requests to a protected site would be blocked even though the user has a valid certificate. Instead of blocking, the Worker answers `421 Misdirected Request`, which makes the browser open a new connection, send the certificate, and retry automatically.

## Behavior

| `request.cf.tlsClientAuth` | Response |
|---|---|
| No certificate presented | `421 Client certificate required` |
| Certificate invalid or revoked | `403 Client certificate rejected` |
| Certificate verified | Passed to the origin unmodified |

Rejections are logged as JSON, without cookies, `Authorization` headers or bodies.

## Usage

```bash
npm install
npm test
npx wrangler login
npx wrangler deploy
```

After deploying, set each route's failure mode to **Fail closed** in the dashboard. Wrangler does not manage it, and fail open lets requests through without a certificate once the daily request limit is reached.
