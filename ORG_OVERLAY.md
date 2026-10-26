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

A renderer-designated `authoritativeIngress` with `identityProfile`,
`identityGeneration` and `identityScope` mints a private request-context proof.
A profileless legacy Pangolin-generated consumer can consume only that proof,
bound to the unchanged transport, Host and canonical forwarding fields. A normal
instance cannot mint delegated authority. An explicitly configured identity
profile re-resolves the original assertions under its own policy and rejects
mismatch; a stricter profile is never bypassed by context reuse. Set profile and
generation on consumers that declare identity policy, rather than relying on
legacy CDN options alone. HTTP headers cannot manufacture the private proof.
Cross-process trust requires explicit exact peers on each receiving leg;
backend application proof is separate.

Downstream generators must pin an org commit, copy runtime Go sources and plugin
manifest together, and record all payload hashes. Do not label the resulting
bundle byte-identical to upstream v1.7.0. Validate via `go test ./...` on the gate
runner and actual Traefik local-plugin wire controls before deployment.
