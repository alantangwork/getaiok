import { invoke } from "@tauri-apps/api/core";
import type {
  BrowserNetworkProbe,
  BrowserProbeSource,
  GetAiOkCheckResult,
  HistoryEntry,
} from "./types";

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
  asn: "AS36352",
  ip_version: "IPv4",
  browser_probe_sources: [
    {
      name: "ipapi.co",
      ip: "192.129.161.49",
      country: "United States",
      region: "California",
      city: "Los Angeles",
      isp: "HostPapa",
      org: "RackNerd LLC",
      asn: "AS36352",
      timezone: "America/Los_Angeles",
      error: null,
    },
    {
      name: "ipwho.is",
      ip: "192.129.161.49",
      country: "United States",
      region: "California",
      city: "Los Angeles",
      isp: "HostPapa",
      org: "RackNerd LLC",
      asn: "36352",
      timezone: "America/Los_Angeles",
      error: null,
    },
  ],
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

export async function runGetAiOkCheck(
  browserProbe?: BrowserNetworkProbe,
): Promise<GetAiOkCheckResult> {
  return invoke<GetAiOkCheckResult>("run_get_ai_ok_check", {
    browserProbe: browserProbe ?? null,
  });
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

export async function collectBrowserNetworkProbe(): Promise<BrowserNetworkProbe> {
  const sources = await Promise.all([
    fetchIpapi(),
    fetchIpwho(),
    fetchIpify("api.ipify.org"),
    fetchIpify("api64.ipify.org"),
    fetchCloudflareTrace(),
  ]);
  const successful = sources.filter((source) => source.ip);
  const primary = successful.find((source) => source.country || source.asn) ?? successful[0];
  const exitIp = primary?.ip ?? null;

  return {
    exit_ip: exitIp,
    ip_version: ipVersion(exitIp),
    country: firstValue(successful.map((source) => source.country)),
    region: firstValue(successful.map((source) => source.region)),
    city: firstValue(successful.map((source) => source.city)),
    isp: firstValue(successful.map((source) => source.isp)),
    org: firstValue(successful.map((source) => source.org)),
    asn: firstValue(successful.map((source) => source.asn)),
    timezone: firstValue(successful.map((source) => source.timezone)),
    sources,
  };
}

async function fetchIpapi(): Promise<BrowserProbeSource> {
  try {
    const data = await fetchJson("https://ipapi.co/json/");
    return {
      name: "ipapi.co",
      ip: stringOrNull(data.ip),
      country: stringOrNull(data.country_name),
      region: stringOrNull(data.region),
      city: stringOrNull(data.city),
      isp: stringOrNull(data.org),
      org: stringOrNull(data.org),
      asn: stringOrNull(data.asn),
      timezone: stringOrNull(data.timezone),
      error: null,
    };
  } catch (error) {
    return failedSource("ipapi.co", error);
  }
}

async function fetchIpwho(): Promise<BrowserProbeSource> {
  try {
    const data = await fetchJson("https://ipwho.is/");
    if (data.success === false) {
      throw new Error(String(data.message ?? "request failed"));
    }
    return {
      name: "ipwho.is",
      ip: stringOrNull(data.ip),
      country: stringOrNull(data.country),
      region: stringOrNull(data.region),
      city: stringOrNull(data.city),
      isp: stringOrNull(data.connection?.isp),
      org: stringOrNull(data.connection?.org),
      asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
      timezone: stringOrNull(data.timezone?.id),
      error: null,
    };
  } catch (error) {
    return failedSource("ipwho.is", error);
  }
}

async function fetchIpify(host: string): Promise<BrowserProbeSource> {
  try {
    const data = await fetchJson(`https://${host}?format=json`);
    return {
      name: host,
      ip: stringOrNull(data.ip),
      country: null,
      region: null,
      city: null,
      isp: null,
      org: null,
      asn: null,
      timezone: null,
      error: null,
    };
  } catch (error) {
    return failedSource(host, error);
  }
}

async function fetchCloudflareTrace(): Promise<BrowserProbeSource> {
  try {
    const text = await fetchText("https://www.cloudflare.com/cdn-cgi/trace");
    const parsed = Object.fromEntries(
      text
        .split("\n")
        .map((line) => line.split("="))
        .filter((parts) => parts.length === 2),
    );
    return {
      name: "Cloudflare trace",
      ip: stringOrNull(parsed.ip),
      country: stringOrNull(parsed.loc),
      region: null,
      city: stringOrNull(parsed.colo),
      isp: null,
      org: null,
      asn: null,
      timezone: null,
      error: null,
    };
  } catch (error) {
    return failedSource("Cloudflare trace", error);
  }
}

async function fetchJson(url: string): Promise<any> {
  const response = await fetchWithTimeout(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function fetchText(url: string): Promise<string> {
  const response = await fetchWithTimeout(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.text();
}

async function fetchWithTimeout(url: string) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 8000);
  try {
    return await fetch(url, {
      cache: "no-store",
      signal: controller.signal,
    });
  } finally {
    window.clearTimeout(timer);
  }
}

function failedSource(name: string, error: unknown): BrowserProbeSource {
  return {
    name,
    ip: null,
    country: null,
    region: null,
    city: null,
    isp: null,
    org: null,
    asn: null,
    timezone: null,
    error: error instanceof Error ? error.message : String(error),
  };
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function firstValue(values: Array<string | null>): string | null {
  return values.find((value) => value && value.trim()) ?? null;
}

function ipVersion(ip: string | null): "IPv4" | "IPv6" | "unknown" {
  if (!ip) return "unknown";
  return ip.includes(":") ? "IPv6" : "IPv4";
}
