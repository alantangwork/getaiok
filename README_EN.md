# get ai ok

English | [中文](./README.md)

**get ai ok** is a desktop network readiness checker for AI tools. It helps users, especially users in mainland China, verify whether their current network environment is ready for Claude Code, Codex, OpenAI CLI, and similar AI tools.

It does not provide proxy services and does not automatically change system settings. Its purpose is to make the current AI access path visible: IP, DNS, proxy, timezone, endpoint configuration, and related risk signals.

## Features

- One-click AI network environment check
- Detect real IP, exit IP, IPv6, DNS, proxy environment, and TUN/VPN hints
- Show exit IP country, region, city, ISP, organization, and timezone
- Identify data center IPs, proxy IPs, high-risk IPs, and abuse records
- Check Claude Code endpoint configuration
- Check Codex / OpenAI CLI API Key, Base URL, and proxy environment variables
- Output low, medium, or high risk conclusion
- Provide beginner-friendly summary and developer details
- Provide repair guides
- Save the latest 50 local check history records
- Open as a compact borderless floating window with a full report view

## Use Cases

- Claude Code cannot connect or behaves unstably
- Codex / OpenAI CLI does not use the expected proxy
- You want to check whether a proxy node is suitable for AI tools
- You want to inspect DNS, IPv6, timezone, data center IP, or related environment risks
- You want to run a quick network check before launching AI tools

## Privacy

Before the first check, the app asks you to confirm third-party online checks.

During detection, the app may request third-party IP information or risk assessment services to query exit IP, location, risk score, and abuse records.

get ai ok does not upload:

- API Keys
- Proxy passwords
- Local configuration files
- Full Claude / OpenAI secrets

Check history is saved locally by default. History records may contain sensitive information such as IP addresses, regions, proxy endpoints, and Base URLs. Be careful when sharing exported reports or screenshots.

## Development

Current first target platform: Windows

Required:

- Node.js
- Rust
- Microsoft Edge WebView2 Runtime
- Windows build environment required by Tauri 2

Install dependencies:

```powershell
npm install
```

Start frontend preview:

```powershell
npm run dev
```

Start desktop app:

```powershell
npm run tauri dev
```

Build frontend:

```powershell
npm run build
```

Build desktop installer:

```powershell
npm run release
```

## Usage

1. Open get ai ok.
2. Confirm the third-party online check notice on first use.
3. Click "Start Check".
4. Review the risk conclusion in the floating window.
5. Click "Full Report" for technical details.
6. If issues are detected, follow the repair guide.
7. Click "Check Again" after making changes.

## Risk Levels

- **Low risk**: The environment looks ready for AI tools.
- **Medium risk**: Some issues need attention before use.
- **High risk**: Significant risks were detected; direct use is not recommended.

Risk evaluation considers IPv6, DNS, proxy chain, exit IP, IP risk score, abuse records, timezone consistency, and Claude/Codex endpoint configuration.

## Notes

get ai ok is not an official risk assessment tool for any AI platform. It only helps detect common local network and configuration issues.

This project is still in an early stage. Issues and suggestions are welcome.
