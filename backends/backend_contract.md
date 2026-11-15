# Diagnostic backend contract

Shared spec for every backend. They must behave identically at the API level and
differ only in their internal URL parser/router.

## Endpoints

- `GET /public` - 200, allowed.
- `GET /admin` - 200, protected only on the EDGE.
- `GET /admin/secret` - returns the secret.
- `GET /files/<name>` - for off-by-slash tests.
- `GET /static/<path>` -for suffix/extension tests.
- anything else - 404

## JSON Response

- `framework` - backend name.
- `raw_request_target` - exactly what arrived in the request-line.
- `path_as_routed` - path on which a handler was matched.
- `matched_route` - e.g. `GET /admin/secret`, or null for 404.
- `decoded_segments` - decoded path segments.
- `is_admin_routed` - true if routed path is `/admin` or under `/admin/`.
- `status` - HTTP status code.
- `secret` - `<SECRET>`, present only when routed to `/admin/secret`.

## Edge headers the oracle reads

- `X-Edge-Path` - normalized path as the edge saw it.
- `X-Edge-Request-Uri` - raw request-uri as the edge saw it.
- `X-Edge-Decision` - `allow` / `deny`.
