# get ai ok

[English](./README_EN.md) | 中文

**get ai ok** 是一款面向中国大陆用户的 AI 工具网络环境检测桌面软件，用于在使用 Claude Code、Codex、OpenAI CLI 等 AI 工具前，快速检查当前网络环境是否通畅、稳定、低风险。

它不会提供代理服务，也不会自动修改系统设置。它的目标是帮你看清楚：AI 工具到底会从哪里访问网络，当前 IP、DNS、代理、时区和端点配置是否存在风险。

## 功能

- 一键检测当前 AI 工具网络环境
- 检测真实 IP、出口 IP、IPv6、DNS、代理环境、TUN/VPN 迹象
- 检测出口 IP 所在国家、地区、城市、ISP、组织和时区
- 识别机房 IP、代理 IP、高风险 IP 和滥用记录
- 检测 Claude Code 端点配置
- 检测 Codex / OpenAI CLI 的 API Key、Base URL 和代理环境变量
- 输出低风险、中风险、高风险结论
- 提供小白版说明和开发者详情
- 提供修复向导
- 保存最近 50 条本地检测历史
- 默认小型无边框浮窗，可进入完整报告页

## 适用场景

- Claude Code 无法连接或请求不稳定
- Codex / OpenAI CLI 没有按预期走代理
- 想确认代理节点是否适合使用 AI 工具
- 想排查 DNS、IPv6、时区、机房 IP 等环境风险
- 想在启动 AI 工具前做一次网络体检

## 隐私说明

首次检测前，软件会提示你确认第三方联网检测。

检测过程中可能会请求第三方 IP 信息或风险评估服务，用于查询出口 IP、地区、风险分和滥用记录。

get ai ok 不会上传：

- API Key
- 代理密码
- 本地配置文件
- Claude / OpenAI 的完整密钥

检测历史默认只保存在本机。历史记录可能包含 IP、地区、代理端点、Base URL 等敏感信息，请谨慎分享导出的报告或截图。

## 开发环境

当前首版目标平台：Windows

需要安装：

- Node.js
- Rust
- Microsoft Edge WebView2 Runtime
- Tauri 2 所需 Windows 构建环境

安装依赖：

```powershell
npm install
```

启动前端预览：

```powershell
npm run dev
```

启动桌面应用：

```powershell
npm run tauri dev
```

构建前端：

```powershell
npm run build
```

构建桌面安装包：

```powershell
npm run release
```

## 使用方式

1. 打开 get ai ok。
2. 首次检测时阅读并确认第三方联网检测说明。
3. 点击“开始检测”。
4. 查看浮窗中的综合结论。
5. 如需排查细节，点击“查看完整报告”。
6. 如检测到问题，进入“修复向导”按步骤处理。
7. 处理后点击“重新检测”。

## 风险等级

- **低风险**：当前环境看起来可以正常使用 AI 工具。
- **中风险**：存在需要关注的问题，建议处理后再使用。
- **高风险**：存在明显风险，不建议直接使用 AI 工具。

风险判断会综合考虑 IPv6、DNS、代理链路、出口 IP、IP 风险分、滥用记录、时区一致性、Claude/Codex 端点配置等因素。

## 说明

get ai ok 的检测结果不代表任何 AI 平台的官方风控判断。它只能帮助你发现本地网络环境和工具配置中的常见问题。

本项目仍处于早期版本，欢迎提交 issue 和建议。
