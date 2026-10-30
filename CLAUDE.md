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
# Real use: the exe requires admin (app.manifest requireAdministrator)
bin\Release\net8.0-windows\WinEtherCloneApe.exe
```

Only the .NET 9 SDK is installed; it builds the net8.0-windows target fine. Desktop runtimes 8 and 9 are installed.

Installed copy: `%LOCALAPPDATA%\Programs\WinEtherCloneApe\WinEtherCloneApe.exe`, Start Menu shortcut "WinEtherCloneApe". Re-publish there after changes:
`dotnet publish WinEtherCloneApe.csproj -c Release -o "$env:LOCALAPPDATA\Programs\WinEtherCloneApe"` (name the .csproj; publishing the .sln with -o warns). GitHub releases get a zip of that folder.

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
- `IpUtil.cs` - IP helpers plus `LocalNetwork` (this PC's addresses, subnet broadcasts, DNS servers, gateways)
- `AppSettings.cs` - `%LOCALAPPDATA%\WinEtherCloneApe\settings.json` (last adapter, Zenmap path, online lookups)

## Architecture notes

- Capture thread only parses packets into `PacketInfo` and enqueues them (capped at 200k). A 100ms DispatcherTimer drains the queue and owns all node/edge state, so there is no shared mutable state across threads.
- Shapes are created once per node/edge and updated each tick (not cleared and redrawn). This is what makes tooltips and context menus work.
- Node color priority: Threat > Broadcast > DNS server > Provider > Local > Other (`NetworkNode.Category`). Red is reserved for threats.
- Broadcast detection: subnet broadcast addresses, 255.255.255.255, multicast, AND Ethernet destination ff:ff:ff:ff:ff:ff. ARP requests are drawn to the 255.255.255.255 node. Broadcast lines are grey.
- DNS server detection: the endpoint using port 53/853, plus adapter DNS servers and known public resolvers.
- Provider detection: ASN from ip-api, then reverse DNS host suffix, then org name keywords.
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
- abuse.ch SSLBL IP list stopped updating in Jan 2025 (comments only), so it was removed from the feeds.
