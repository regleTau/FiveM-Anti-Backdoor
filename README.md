# FiveM Anti Backdoor & Bad Code Remover

A professional Windows desktop application specifically built to scan and remove backdoors, bad code, remote executors, credential stealers, and obfuscation from FiveM server resources.

## Features

- **Static Analysis Only**: Safe to use. The scanner never executes scanned Lua, JavaScript, or manifest scripts.
- **FiveM-Specific Signature Engine**: Tailored scanner targeting common backdoor patterns, Discord webhook abuse, environment variable exfiltration, and unauthorized network events.
- **Obfuscation Detection**: Flags heavy string character array formatting, Base64 blobs, compiled Lua bytecodes, and high-entropy code segments.
- **Safe Cleaner**: Previews and removes confirmed malicious segments with automated directory backups and full restoration support.
- **Quarantine Hub**: Safely isolates suspicious assets from loading inside your FiveM server environment.
- **Interactive Reports**: Automatically outputs reports to clean HTML dashboards or structured JSON data feeds.
- **Real-Time Monitor**: Background folder observer rescanning modified resource files instantly.

## Installation

Run the following command to install required Python libraries:

```bash
pip install -r requirements.txt
```

## Running the Application

To launch the PySide6 UI:

```bash
python main.py
```

## Downloads

Download the latest Windows executable from the GitHub Releases page:

- [FiveM Anti Backdoor v1.0.0](https://github.com/regleTau/FiveM-Anti-Backdoor/releases/tag/v1.0.0)

## Compiling into a Standalone Executable (.exe)

Compile the application to a single binary using the provided build script:

```batch
build.bat
```
