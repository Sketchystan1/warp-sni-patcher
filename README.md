# WARP SNI Patcher

Change Cloudflare WARP's SNI and registration hostnames on Windows, Linux, and macOS.

## Use

1. Install Cloudflare WARP.
2. Download the package for your system from [Releases](https://github.com/Sketchystan1/warp-sni-patcher/releases/latest) and extract it.
3. Start the patcher:

   - **Windows:** open `warp-sni-patcher.exe` and allow administrator access.
   - **Linux/macOS:** open a terminal in the extracted folder and run `sudo ./warp-sni-patcher --gui`.

4. Enter the hostnames you want to use and click **Patch**. On macOS, follow the steps below before and after patching.

Click **Restore** to undo the patch. Keep the `.bak` backup file; Restore needs it. WARP updates may undo the patch.

**macOS:** Before Patch or Restore, run `warp-cli registration delete`. Afterward, run `warp-cli registration new`, or sign in again for Zero Trust. Use WARP's default tunnel mode; PacketTunnel is not supported. macOS with SIP on has not been tested.

**Linux:** Needs an X11/XWayland desktop and system libraries compatible with Ubuntu 22.04.

For command-line help, run `./warp-sni-patcher --help`.
