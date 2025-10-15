# WinEtherCloneApe

[![Windows](https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet)](https://dotnet.microsoft.com/)
[![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=c-sharp&logoColor=white)](https://docs.microsoft.com/en-us/dotnet/csharp/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)

The files are too large for github - download them here from google drive: https://drive.google.com/file/d/1_75n3IlnkvS99D7Hj4l8Xw6NTwoMI0sL/view?usp=sharing

**A real-time network traffic visualizer for Windows** - bringing the power of Linux's EtherApe to the Windows platform with a modern implementation.

![WinEtherCloneApe Screenshot](screenshot.png)

## Features

### Core Capabilities
- **Real-time packet capture** using WinPcap/Npcap technology
- **Dynamic visualization** with circular network topology
- **Intelligent DNS resolution** with automatic service identification
- **Bandwidth-based node scaling** - node size reflects traffic volume
- **Auto-fade technology** - connections fade after 60 seconds of inactivity

### Visual Protocol Identification

| Element | Description | Color |
|---------|-------------|-------|
| **Local Network Nodes** | Devices on your local network (192.168.x.x, 10.x.x.x) | Green |
| **External Nodes** | Internet hosts and servers | Red |
| **TCP Connections** | Transmission Control Protocol traffic | Cyan |
| **UDP Traffic** | User Datagram Protocol packets | Green |
| **ICMP Packets** | Internet Control Message Protocol | Yellow |
| **Other Protocols** | Unidentified or other protocol types | Magenta |

### Service Identification
Automatic detection and labeling of major service providers:
- Amazon AWS
- Microsoft Azure
- Google Cloud Platform
- Cloudflare
- Meta/Facebook
- Akamai CDN
- Common DNS servers (Google DNS, OpenDNS, Cloudflare DNS)

## Installation

### Prerequisites
- Windows 10/11 (64-bit)
- .NET 8.0 Runtime ([Download](https://dotnet.microsoft.com/download/dotnet/8.0))
- Npcap ([Download](https://npcap.com/))
- Administrator privileges

### Quick Start

1. **Install Npcap**
   - Download from https://npcap.com/
   - During installation, ensure "Install Npcap in WinPcap API-compatible Mode" is checked

2. **Download the latest release** from the [Releases](https://github.com/powellga/WinEtherCloneApe/) page

3. **Run as Administrator**
   - Right-click `WinEtherCloneApe.exe`
   - Select "Run as administrator"

## Building from Source

### Requirements
- Visual Studio 2022
- .NET 8.0 SDK

### Build Steps
```bash
# Clone the repository
git clone https://github.com/powellga/WinEtherCloneApe.git
cd WinEtherCloneApe

# Open in Visual Studio
start WinEtherCloneApe.sln

# Or build via command line
dotnet build --configuration Release
```

### Required NuGet Packages
```xml
<PackageReference Include="SharpPcap" Version="6.3.0" />
<PackageReference Include="PacketDotNet" Version="1.4.7" />
```

## Usage

1. **Launch** the application with Administrator privileges
2. **Select** your network interface from the dropdown menu
3. **Click** "Start Capture" to begin monitoring
4. **Observe** real-time network connections and traffic patterns
5. **Stop** monitoring with the "Stop Capture" button

### Interface Controls
- **Start/Stop Capture** - Control packet capture
- **Clear** - Reset the visualization and clear all nodes
- **Network Interface Selector** - Choose which network adapter to monitor
- **Status Bar** - View packet count, total bytes, and active nodes

## Technical Architecture

```
WinEtherCloneApe/
├── MainWindow.cs           # Core application and visualization logic
├── NetworkNode.cs          # Node data structure and properties
├── NetworkEdge.cs          # Connection representation
├── DNS Resolution          # Asynchronous hostname resolution
└── Packet Processing       # SharpPcap packet capture and analysis
```

### Key Technologies
- **WPF (Windows Presentation Foundation)** for UI rendering
- **SharpPcap** for packet capture functionality
- **PacketDotNet** for packet parsing and protocol identification
- **Concurrent Collections** for thread-safe data management

## Performance Characteristics

- **Memory Management**: Automatic cleanup of inactive connections after 2 minutes
- **Update Frequency**: 100ms refresh rate for smooth visualization
- **Scalability**: Efficiently handles hundreds of concurrent connections
- **CPU Usage**: Optimized rendering with WPF hardware acceleration

## Known Limitations

- Some IP addresses may not resolve to hostnames due to missing PTR records
- IPv6 support is limited in the current implementation
- High-traffic networks may experience label overlap in dense visualizations
- DNS resolution depends on reverse DNS configuration by service providers

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -m 'Add YourFeature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built by Gregg Powell (g.a.powell@protonmail.com)
- Inspired by [EtherApe](https://etherape.sourceforge.io/) for Linux
- Built with [SharpPcap](https://github.com/chmorgan/sharppcap) by Chris Morgan
- Packet parsing via [PacketDotNet](https://github.com/chmorgan/packetdotnet)
- Community feedback and contributions

---

<div align="center">
<strong>WinEtherCloneApe</strong><br>
Real-time Network Visualization for Windows
</div>
