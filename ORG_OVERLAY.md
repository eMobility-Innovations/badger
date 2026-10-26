# Supported runtime and identity boundary

This org fork retains upstream history and the upstream module path for Traefik's
local-plugin loader. The source authority is this repository, not a downstream
plugin bundle. Generic upstream: https://github.com/fosrl/badger.

The supported runtime payload starts from upstream v1.7.0,
`926d126720c5a7666f4f281692134ad752a55bf0`. The fork began at fresh upstream/main
`2b781d2`; the explicit baseline commit restores `main.go` and `version/version.go`
to the deployed 1.7 payload. Its main.go SHA256 before the identity patch is
`64602dd5771ea8f0b95476931af186f8fac09b109ce456364bc48876c0696db6`.
The 1.8 permanent/temporary redirect extension is deliberately outside this
support baseline. Existing authentication response behavior remains 1.7.

The identity overlay adds `trustedProxyIPs`, separate from CDN `trustip`.
Only an actual approved CDN peer supplies the configured vendor client header;
an infrastructure peer supplies a right-to-left XFF chain. Direct requests use
their transport address. Malformed or repeated trusted assertions return 400.
Every request receives canonical XFF/X-Real-IP, public authority, scheme and port.
The original transport address remains in RemoteAddr and Traefik access logs.

Optional `allowedHosts` and `allowedSchemes` constrain route-authorized public
context. Without a host declaration, a trusted forwarded authority must equal
the current Host. Scheme is always HTTP/HTTPS. Global and broad private proxy
trust is rejected. No PROXY protocol or insecure forwarding is enabled.

A private request-context record preserves the normalized result across multiple
Badger instances in one Traefik chain, including Pangolin-generated middleware.
HTTP headers cannot manufacture that record. Cross-process trust still requires
explicit exact peers on each receiving leg; backend application proof is separate.

Downstream generators must pin an org commit, copy runtime Go sources and plugin
manifest together, and record all payload hashes. Do not label the resulting
bundle byte-identical to upstream v1.7.0. Validate via `go test ./...` on the gate
runner and actual Traefik local-plugin wire controls before deployment.
