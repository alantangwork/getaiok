import { invoke } from "@tauri-apps/api/core";
import type { GetAiOkCheckResult, HistoryEntry } from "./types";

const demoResult: GetAiOkCheckResult = {
  id: "demo",
  checked_at: "2026-07-02 17:20:00",
  risk_level: "medium",
  beginner_summary: "建议先处理 2 个问题，再使用 AI 工具。",
  real_ip: "49.77.16.209",
  ipv6: null,
  dns_servers: ["172.18.0.2", "192.168.31.1"],
  exit_ip: "192.129.161.49",
  country: "United States",
  region: "California",
  city: "Los Angeles",
  isp: "HostPapa",
  org: "RackNerd LLC",
  exit_timezone: "America/Los_Angeles",
  proxy_envs: {},
  system_proxy_status: "warning",
  system_proxy_message: "系统代理未开启",
  tun_vpn_status: "warning",
  tun_vpn_message: "未检测到明显 TUN/VPN 网卡",
  hosting: true,
  proxy: null,
  risk_score: null,
  risk_query_message: "风险查询失败：Read timed out",
  spam_listed: null,
  spam_message: "滥用记录查询失败：Read timed out",
  system_timezone: "China Standard Time",
  cli_timezone: "China Standard Time",
  timezone_matched: false,
  claude: {
    installed: true,
    base_url: null,
    endpoint_status: "ok",
    message: "官方直连（未设置 ANTHROPIC_BASE_URL）",
  },
  codex: {
    openai_api_key_present: true,
    openai_base_url: null,
    proxy_env_present: false,
    endpoint_status: "ok",
    message: "未设置 OpenAI Base URL，默认官方端点",
  },
  suggestions: [
    "终端代理未设置，Claude/Codex 可能不会走代理。",
    "本机时区与出口 IP 所在时区不一致。",
  ],
  repair_guides: [
    {
      id: "proxy-env",
      title: "终端代理可能未设置",
      summary: "Claude Code、Codex 这类命令行工具，不一定会自动使用系统代理。",
      steps: [
        "打开你的代理软件。",
        "找到本地 HTTP 或 SOCKS5 端口。",
        "在 PowerShell 中设置代理环境变量。",
        "重新运行 get ai ok 检测。",
      ],
      developer_commands: [
        '$env:HTTP_PROXY="http://127.0.0.1:7890"',
        '$env:HTTPS_PROXY="http://127.0.0.1:7890"',
        '$env:ALL_PROXY="socks5://127.0.0.1:7891"',
      ],
    },
  ],
  developer_details: [
    {
      title: "基础网络",
      rows: [
        { label: "真实 IP", value: "49.77.16.209", status: "unknown" },
        { label: "IPv6", value: "未知", status: "ok" },
        { label: "DNS", value: "172.18.0.2, 192.168.31.1", status: "ok" },
      ],
    },
    {
      title: "Claude / Codex",
      rows: [
        { label: "Claude", value: "官方直连", status: "ok" },
        { label: "Codex", value: "代理变量未设置", status: "warning" },
      ],
    },
  ],
};

export function getDemoResult(): GetAiOkCheckResult {
  return demoResult;
}

export async function runGetAiOkCheck(): Promise<GetAiOkCheckResult> {
  return invoke<GetAiOkCheckResult>("run_get_ai_ok_check");
}

export async function listCheckHistory(): Promise<HistoryEntry[]> {
  return invoke<HistoryEntry[]>("list_check_history");
}

export async function deleteCheckHistory(id: string): Promise<HistoryEntry[]> {
  return invoke<HistoryEntry[]>("delete_check_history", { id });
}

export async function clearCheckHistory(): Promise<void> {
  return invoke<void>("clear_check_history");
}
