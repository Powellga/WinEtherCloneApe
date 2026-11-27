# WinEtherCloneApe

This file provides guidance to Claude Code when working with code in this repository.

## Project

**WinEtherCloneApe** is Gregg's C# / .NET 8 WPF network traffic visualizer for Windows, inspired by Linux's EtherApe. It captures packets with SharpPcap/Npcap and draws hosts on two rings (inner = local network, outer = internet) with lines colored by protocol.

Not to be confused with **WinEtherApe**, the older Python/PyQt5 version (workspace `winetherape`, code in `C:\Users\gregg\_____PYTHON_PROJECTS\WinEtherApe`, repo Powellga/WinEtherApe).

- GitHub: https://github.com/Powellga/WinEtherCloneApe (public, branch `master`, Powellga account)
- The workspace folder IS the git repo.

## Build and run

```powershell
dotnet build -c Release
# Demo mode: simulated traffic, no adapter or admin needed when started via dotnet (skips the UAC manifest)
dotnet bin\Release\net8.0-windows\WinEtherCloneApe.dll --demo            # add --open-map to auto-open the World Map after 20s
# --capture-host <ip>: starts live capture on the last-used adapter and opens a packet capture for that IP (used to test packet capture without the right-click menu)
# --zoom <factor>: starts zoomed in. Use it to test zoom: posted WM_MOUSEWHEEL and WM_KEYDOWN messages do not reach WPF (wheel goes to the element under the real pointer, keys need focus)
# Real use: the exe requires admin (app.manifest requireAdministrator)
bin\Release\net8.0-windows\WinEtherCloneApe.exe
```

Only the .NET 9 SDK is installed; it builds the net8.0-windows target fine. Desktop runtimes 8 and 9 are installed.

## Releasing

1. Bump `<Version>` in WinEtherCloneApe.csproj.
2. `.\build-release.ps1` creates `artifacts\WinEtherCloneApe-<ver>-portable.exe` (self-contained single file, ~69 MB) and `artifacts\WinEtherCloneApe-<ver>-Setup.exe` (Inno Setup, ~66 MB). Inno Setup 6 is installed per-user at `%LOCALAPPDATA%\Programs\Inno Setup 6`. The script downloads the WebView2 bootstrapper into `installer\redist` (gitignored).
3. Install on this PC: `artifacts\...-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /CURRENTUSER` (per-user, no UAC; upgrades in place). Installed to `%LOCALAPPDATA%\Programs\WinEtherCloneApe`, Start Menu shortcut "WinEtherCloneApe", uninstaller in Apps & features.
4. `gh release create v<ver>` with both files. Creating a release needs Gregg's approval in the permission prompt.

Installer details (`installer\WinEtherCloneApe.iss`): per-user by default (PrivilegesRequired=lowest, dialog to choose all users), installs WebView2 if missing, cannot bundle Npcap (license) so it shows an info page and offers npcap.com when Npcap is missing, optional Nmap download link, uninstall removes caches but keeps settings.json and threats.log.

To test a build without the UAC prompt, publish with `-p:ApplicationManifest=<copy of app.manifest set to asInvoker>`. On this PC Npcap allows non-admin capture, so live capture works in that test build. Buttons can be pressed safely with UI Automation InvokePattern (no mouse movement).

Do NOT test the GUI by moving the mouse (SetCursorPos/mouse_event): Windows often refuses to bring the app to the front, and the click lands in whatever window is on top. On 2026-10-30 a right-click pasted text into Gregg's open terminal. Screenshots via PrintWindow are safe.

## Files

- `App.cs` - entry point, `--demo` / `--open-map` flags
- `MainWindow.cs` - UI built in code (no XAML), capture, packet queue, rendering, tooltip, right-click menu, demo traffic
- `Models.cs` - NetworkNode (with its WPF shapes), NetworkEdge, GeoInfo, NodeCategory
- `NodePalette.cs` - all colors, top-10 provider definitions (ASNs, host suffixes, org keywords), known public DNS resolvers
- `ThreatIntel.cs` - blocklist download/cache/merge/binary-search lookup
- `LookupServices.cs` - DnsResolverService (reverse DNS, 4s timeout, 8 concurrent) and IpInfoService (ip-api.com batch, 100 IPs per call, every 4.5s)
- `MapWindow.cs` - Leaflet 1.9.4 map in WebView2, served from a virtual host `https://winetherape.map/`
- `ExternalTools.cs` - Zenmap launch (`zenmap.exe -t <ip> -p "<profile>"`, auto-starts the scan), browser via explorer.exe (so the browser is not elevated)
- `HostCaptureWindow.cs` - per-host packet capture: `HostCapture` (filled on the capture thread from `OnPacketArrival`) and a Wireshark-style window (live list, verbose decode plus hex dump, Save .pcap via `CaptureFileWriterDevice`, Open in Wireshark via explorer.exe so Wireshark is not elevated). Saves to `%USERPROFILE%\WinEtherCloneApe Captures` (deliberately not Documents: on this PC Documents is the TEMARK OneDrive, and captures hold raw traffic). Caps: 200k packets or 512 MB, then auto-pause.
- `SshDialog.cs` - user name and port prompt; values saved in settings (SshUser, SshPort)
- `TailscaleService.cs` - runs `tailscale status --json` (Program Files\Tailscale) at startup and every 60s for device names, OS, online state and tunnel endpoints (CurAddr). Without the CLI: fd7a:115c:a1e0::/48 always, 100.64.0.0/10 only when a Tailscale adapter is up (that range is also ISP carrier-grade NAT), 100.100.100.100 = MagicDNS, *.tailscale.com host names = Tailscale servers. Skipped in demo mode (demo sets AssumeTailnet instead).
- `IpUtil.cs` - IP helpers plus `LocalNetwork` (this PC's addresses, subnet broadcasts, DNS servers, gateways)
- `AppSettings.cs` - `%LOCALAPPDATA%\WinEtherCloneApe\settings.json` (last adapter, Zenmap path, online lookups)

## Architecture notes

- Capture thread only parses packets into `PacketInfo` and enqueues them (capped at 200k). A 100ms DispatcherTimer drains the queue and owns all node/edge state, so there is no shared mutable state across threads.
- Shapes are created once per node/edge and updated each tick (not cleared and redrawn). This is what makes tooltips and context menus work.
- Node color priority: Threat > Broadcast > Tailscale > DNS server > Provider > Local > Other (`NetworkNode.Category`). Red is reserved for threats. Tailscale is lavender with a steady dashed ring (the Halo ellipse, which is the pulsing red ring for threats).
- Right-click Connect items: browser `http://ip/` and `https://ip/` via explorer.exe; SSH via `%SystemRoot%\System32\OpenSSH\ssh.exe` in Windows Terminal (`wt.exe new-tab`), falling back to `cmd /k`. User names are validated (`ExternalTools.IsSafeUserName`) because they go on a command line.
- Broadcast detection: subnet broadcast addresses, 255.255.255.255, multicast, AND Ethernet destination ff:ff:ff:ff:ff:ff. ARP requests are drawn to the 255.255.255.255 node. Broadcast lines are grey.
- DNS server detection: the endpoint using port 53/853, plus adapter DNS servers and known public resolvers.
- Provider detection: ASN from ip-api, then reverse DNS host suffix, then org name keywords.
- Zoom and pan (region "Zoom and pan" in MainWindow): node.Position is the layout (ring) position; `ToScreen()` applies `zoom` and `pan` at draw time in `RenderView()`. It is semantic zoom, not a RenderTransform: positions spread by the zoom factor while dots grow by zoom^0.3 and fonts by zoom^0.25, so crowded labels separate. `LayoutAndRender()` (timer tick) moves nodes along the rings and then calls `RenderView()`; drag/zoom call `RenderView()` only, via `RenderNow()`. Mouse: wheel zooms at the pointer, left-drag pans, double-click resets. Touch: canvas `IsManipulationEnabled` (pinch and pan), and a 650ms press-and-hold timer opens the host menu because manipulation stops touch being promoted to right-click. Keys: + - 0.
- Timing constants at the top of MainWindow: edges fade after 5s and go at 60s; nodes fade after 60s idle and go at 120s; threat nodes stay 600s.

## External services (no keys)

- Threat feeds (cached in `%LOCALAPPDATA%\WinEtherCloneApe\threatfeeds`, refreshed after 12h): FireHOL Level 1, Feodo Tracker, Emerging Threats compromised IPs, CINS Army. FireHOL Level 1 includes private bogon ranges, so private/reserved IPs are excluded before lookup.
- ip-api.com: free tier is HTTP only and non-commercial, 15 batch requests/min. Toggle "Online lookups" turns it off.
- Map tiles: Esri World Dark Gray Base + Reference (no key). CARTO basemaps now need an API key (found 2026-10-30), do not switch back.
- Threat log: `%LOCALAPPDATA%\WinEtherCloneApe\threats.log`.

## Testing approach

Run `--demo`, then screenshot with PrintWindow (PW_RENDERFULLCONTENT) from PowerShell. Demo mode includes one real blocklisted IP (first Feodo entry) so the threat styling can be checked.

## Project Context Log

- 2026-10-30: v2.0.0. Big rewrite of the original single-file v1 (Aug 2025): split into files, stability fixes, threat detection, color palette, Zenmap and Where is? right-click menu, World Map, tooltips, adapter auto-select. The README's old "files too large, download from Google Drive" note was dropped: the repo source was complete (the Drive file was the built program).
- 2026-10-30: GitHub release v2.0.0 published with WinEtherCloneApe-2.0.0-win-x64.zip (framework-dependent publish output): https://github.com/Powellga/WinEtherCloneApe/releases/tag/v2.0.0
- 2026-10-30: v2.0.1 - app icon (app.ico, generated), single-file self-contained build, Inno Setup installer, multicast label fix. Verified: single exe live-captured 60 hosts; silent install, uninstall and reinstall all pass. README screenshot must stay the demo one (a live capture shows Gregg's real hosts, PC name and IPs in a public repo).
- 2026-11-27: v2.1.0 - right-click Connect with browser (80 and 443) and SSH, Tailscale category (lavender, dashed ring, names from `tailscale status --json`), per-host packet capture window with .pcap export. Published as GitHub release v2.1.0 (Setup.exe and portable.exe): https://github.com/Powellga/WinEtherCloneApe/releases/tag/v2.1.0. The 2.0.1 release was never published; 2.1.0 replaces it. Verified live: capture window recorded the router's packets, decode pane works, saved .pcap read by capinfos/tshark (77 packets, Ethernet); Tailscale DERP servers, a tunnel endpoint and a tailnet device were classified. Not exercised by clicking: the SSH and browser menu items (the right-click menu cannot be opened without the mouse).
- 2026-11-27: v2.2.0 - zoom and pan on the main view (mouse wheel, drag, double-click reset, Reset View button, pinch and finger drag on touch screens, press-and-hold for the host menu, + - 0 keys), Details... menu item. Verified: --zoom screenshot shows nodes spread with readable labels, and a real mouse-wheel scroll during the test zoomed around the pointer. Not verified: left-drag pan and touch gestures (no safe way to send them without the real mouse or a touch screen). Published as GitHub release v2.2.0: https://github.com/Powellga/WinEtherCloneApe/releases/tag/v2.2.0. Not yet installed on this PC (the app was open, so the upgrade was not forced).
- abuse.ch SSLBL IP list stopped updating in Jan 2025 (comments only), so it was removed from the feeds.
