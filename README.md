# WARP SNI Patcher

A small tool that patches Cloudflare WARP's `warp-svc.exe` on disk to override the MASQUE tunnel SNI and the registration API hostname.

## How it works

The patcher parses `warp-svc.exe` as a PE image, and for each known hostname it:

1. Overwrites the hostname string in place with the new value (same address, so no pointer repointing needed).
2. Fixes the associated length values — fat-pointer length fields in data, `mov r32, imm32` immediates near the `lea` that loads the hostname, and (registration host only) the parallel ptr/len arrays `warp-svc` indexes at runtime.

MASQUE hostnames are packed string-table literals, so the replacement must fit the original length; the tail is left untouched (Rust `&str` is `(ptr, len)` with no NUL terminator, so the patched length bounds every read). Registration hosts sit in fixed 32-byte slots, so the replacement may be longer, up to the slot capacity.

The original binary is preserved as `<target>.bak`, refreshed whenever the target is still pristine, so re-running after a WARP update stays clean. Patching breaks the Authenticode signature.
