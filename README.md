<p align=center>
  <a href="https://kosm-os.world">
    <img alt="KOSMOS" src="https://reactos.org/wiki/images/0/02/ReactOS_logo.png">
  </a>
</p>

---

<p align=center>
  <a href="https://kosm-os.world">
    <img alt="KOSMOS Release" src="https://img.shields.io/badge/release-alpha-0688CB.svg"></a>
  <a href="https://kosm-os.world/download/">
    <img alt="Download KOSMOS" src="https://img.shields.io/badge/download-latest-0688CB.svg"></a>
  <a href="https://github.com/Endlad2/ReactOS_K/">
    <img alt="License" src="https://img.shields.io/badge/license-GNU_GPL_2.0-0688CB.svg"></a>
  <a href="https://github.com/Endlad2/ReactOS_K/">
    <img alt="GitHub Stars" src="https://img.shields.io/github/stars/Endlad2/ReactOS_K?style=social"></a>
</p>

## Quick Links
[Website](https://kosm-os.world) &bull;
[GitHub](https://github.com/Endlad2/ReactOS_K/) &bull;
[JIRA Bug Tracker](https://jira.kosm-os.world) &bull;
[CDN Mirror](https://cdn.kosm-os.world) &bull;


## What is KOSMOS?

**KOSMOS (ReactOS K)** is a fork of ReactOS based on ReactOS Longhorn, but with a new vision: cloud infrastructure, stability and compatibility with **NT6+ (Windows Vista/7/8/10/11)** and **UWP**.

KOSMOS maintains compatibility with applications and drivers for Windows NT, but goes further: support for modern application formats (AppX, MSIX), cloud technologies and automated development infrastructure.

### KOSMOS abbreviation expansion:
**K** - Cross-platform
**O** - Fault-tolerant
**S** - System with
**M** - Modular
**O** - Cloud
**S** - Structure

### Differences from ReactOS
- **Target compatibility:** NT6+ (not NT5.2/Windows 2003)
- **UWP support:** Web AppX already working (alpha stage)
- **Neptune:** own translator language (Python syntax → C)
- **Auto bugfix:** Deepseek Coder neural network on JIRA
- **KOSMOSBE:** Docker build environment — cross-platform, no hassle
- **Custom hardware build:** user sends log → receives custom image on CDN

### Product quality warning

**KOSMOS is currently in alpha stage.** This means the system is under heavy development, errors and crashes may occur. It is highly recommended to test KOSMOS on virtual machines or computers without critical data. KOSMOS is based on ReactOS, which is also alpha quality.

## Building

![Build](https://github.com/kosmos/kosmos/workflows/Build/badge.svg)

To build KOSMOS you need **KOSMOS Build Environment (KOSMOSBE)** — a Docker image with all necessary tools. It works on Linux, Windows and macOS.

### Quick start

Download KosmosBE from [KosmosBE](https://be.kosm-os.world/)
kosmos-be build

Or use GitHub Actions — builds happen automatically on each push.

### Neptune translator

KOSMOS uses its own language **Neptune**, which translates to C. This allows writing code in Python-like syntax with full C compatibility.

Example code in Neptune:

def main():
    print("Hello from KOSMOS!")

Convert Neptune → C:

neptune n2c main.n -o main.c

Convert entire project C → Neptune:

neptune c2n -r .

### Bootable images

Build bootable ISO:

kosmos-be build bootcd

Ready builds are available on [CDN](https://cdn.kosm-os.world) and mirrors:
- Yandex Disk (For releases)
- Google Drive (For releases)
- TeraBox (Only for custom hardware builds)

## Installing

KOSMOS installs on FAT32 or BtrFS partition (experimental). Write the image to USB/DVD, boot from it and follow the setup instructions.



## Testing

Found a bug? Report it to [JIRA](https://jira.kosm-os.world). Our neural networks will automatically analyze the problem and suggest a patch.

**KOSMOS feature:** Send your boot log through the website — and get a custom build for your hardware within a few days.

## Contributing

KOSMOS is open for contributors! We need:
- C/System programmers
- Testers with exotic hardware
- ARM port enthusiasts
- Everyone who wants a modern open-source OS

Contribution guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)

**Important:** KOSMOS is based on ReactOS and inherits its GPL 2.0 license. Using proprietary Microsoft Windows code is prohibited.

Try cloud-based KOSMOS development with KOSMOS DevCloud:
[DevCloud](https://devcloud.kosm-os.world)

## More information

**KOSMOS is not just a fork.** It's a rethinking of ReactOS for modern realities: clouds, UWP, neural networks, ARM. We don't replace WINE (and actively use its work). We don't try to compete with Linux. KOSMOS is an alternative for those who need a Windows-compatible OS but with a modern architecture and open source.

### How KOSMOS compares to ReactOS

| Feature | ReactOS | KOSMOS |
|---------|---------|--------|
| Target NT version | 5.2 (2003) | 6.0+ (Vista and newer) |
| UWP support | ❌ | ✅ (Web AppX) |
| Neural network auto-bugfix | ❌ | ✅ |
| Docker build environment | ❌ | ✅ |
| Custom hardware build | ❌ | ✅ |
| C→Neptune→C translator | ❌ | ✅ |

## Who is responsible

KOSMOS is created and maintained by enthusiasts led by **Endlad7373 (KOSMOS developer)**. The project is a fork of ReactOS, so we are grateful to everyone who contributed to ReactOS over the years.

Main development happens on [GitHub](https://github.com/Endlad2/ReactOS_K/).

## Links
- [ReactOS — original project](https://reactos.org/)
- [Neptune Language](https://github.com/Endlad2/neptune)


---

<p align=center>
  <i>KOSMOS doesn't wait — KOSMOS does. 🚀</i>
</p>
