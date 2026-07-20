# WARP SNI Patcher

A small tool that patches Cloudflare WARP's `warp-svc.exe` on disk to override the MASQUE SNI hostname. 

## How it works

The patcher parses `warp-svc.exe` as a PE image, and for each known MASQUE hostname it:

1. Overwrites the hostname string in place with the new SNI (same address, so no pointer repointing needed).
2. Fixes the associated length values — fat-pointer length fields in data, and `mov r32, imm32` length immediates near the `lea` that loads the hostname.

Bytes after the new SNI are left untouched: Rust `&str` is `(ptr, len)` with no NUL terminator, so the patched length bounds every read, and preserving the tail avoids corrupting linker-merged suffixes.
