# Sliver GUI embedding patch inventory

Base: `1f69e124e6bf85608efce3495c12eaf5f6b5a95d`.

This branch adds narrow embedding APIs and defensive reassembly limits while
retaining existing desktop viewer feature defaults:

- `ironrdp-client/clipboard-custom` enables the CLIPRDR protocol and custom
  backend factory without `ironrdp-cliprdr-native` or native window-system
  dependencies. Existing `clipboard` implies this feature and retains its
  native backend behavior.
- `ConfigBuilder::with_peer_certificate_policy` selects strict rustls
  verification plus a callback on every certificate, including PKI-valid ones.
  `PeerCertificateStatus` reports typed verification categories. Unknown and
  cryptographic failures cannot be overridden; TLS handshake signature checks
  remain delegated to the strict verifier. This path disables resumption and
  does not enable TLS key logging from environment variables.
- `ConfigBuilder::with_negotiation_cookie` prevents the default username-derived
  pre-TLS routing cookie when the embedder supplies a non-identifying cookie.
- `RdpClient::with_desktop_limits` and `DecodedImage::new_bounded` enforce host
  framebuffer allocation limits before initial/reactivated allocations and
  graphics resets. EGFX's independent compositor allocation limits still apply.
- Static and dynamic channel reassembly rejects advertised or accumulated
  messages above 64 MiB before extending retained buffers. Compressed static
  fragments obey the same actual-byte ceiling. This general limit accommodates
  an uncompressed 4K RGBA frame; backends impose tighter semantic limits (the
  GUI's text clipboard limit is 1 MiB). Invalid dynamic fragment sequences reset
  their retained state, and completed messages transfer their allocation.

The policy callback is synchronous on the TLS handshake thread. An embedder
must deliver its decision on a different thread with cancellation and a bounded
wait. These APIs do not export credentials/session state, inject arbitrary
streams, or implement a native-to-WASM session handoff.

Validation on native Apple Silicon with Rust 1.94.1:

- `cargo check -p ironrdp-client --no-default-features --features rustls,clipboard-custom`
- `cargo check -p ironrdp-client --no-default-features --features native-tls,clipboard`
- `cargo test -p ironrdp-tls --no-default-features --features rustls --lib peer_policy_tests`
- `cargo test -p ironrdp-session --lib host_limit_tests`
- `cargo test -p ironrdp-svc --lib reassembly_limit_tests`
- `cargo test -p ironrdp-dvc --lib complete_data::tests`

Cross-platform GUI packaging and real-server interoperability are validated in
Sliver GUI's own release matrix; these local checks do not certify those targets.
