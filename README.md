# WinEtherCloneApe

A Windows network traffic visualizer inspired by EtherApe for Linux. Real-time visualization of network connections with protocol identification and DNS resolution.

## Features

- **Real-time packet capture** using WinPcap/Npcap
- **Visual network topology** with circular node layout
- **Protocol-based color coding**:
  - TCP (Cyan)
  - UDP (Green) 
  - ICMP (Yellow)
  - Other (Magenta)
- **Node differentiation**:
  - Green nodes: Local network devices
  - Red nodes: External/Internet hosts
- **DNS resolution** for external IPs
- **Dynamic node sizing** based on bandwidth usage
- **Automatic fade-out** after 1 minute of inactivity

## Requirements

- Windows 10/11
- .NET 8.0 Runtime
- [Npcap](https://npcap.com/) (install with WinPcap API-compatible mode)
- Administrator privileges (for packet capture)

## Installation

1. Download and install [Npcap](https://npcap.com/#download)
   - During installation, check "Install Npcap in WinPcap API-compatible Mode"
2. Download the latest release from the Releases section
3. Run WinEtherCloneApe.exe as Administrator

## Building from Source

### Prerequisites
- Visual Studio 2022
- .NET 8.0 SDK

### Build Steps
1. Clone the repository
2. Open `WinEtherCloneApe.sln` in Visual Studio
3. Restore NuGet packages (should happen automatically)
4. Build solution (Ctrl+Shift+B)
5. Run as Administrator (F5)

### Required NuGet Packages
- SharpPcap
- PacketDotNet

## Usage

1. Launch the application (requires Administrator privileges)
2. Select your network interface from the dropdown
3. Click "Start Capture"
4. Watch your network traffic visualized in real-time
5. Click "Stop Capture" to pause monitoring

## License

[Your chosen license - e.g., MIT, GPL, etc.]

## Acknowledgments

- Inspired by [EtherApe](https://etherape.sourceforge.io/) for Linux
- Built with [SharpPcap](https://github.com/chmorgan/sharppcap) for packet capture
- Built by Gregg Powell (g.a.powell@protonmail.com)
