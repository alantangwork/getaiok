export type RiskLevel = "low" | "medium" | "high";

export type CheckStatus = "ok" | "warning" | "danger" | "unknown";

export type ClaudeInfo = {
  installed: boolean | null;
  base_url: string | null;
  endpoint_status: CheckStatus;
  message: string;
  detected_products: string[];
  timezone_advice: string | null;
};

export type CodexInfo = {
  openai_api_key_present: boolean | null;
  openai_base_url: string | null;
  proxy_env_present: boolean;
  endpoint_status: CheckStatus;
  message: string;
  detected_products: string[];
  timezone_advice: string | null;
};

export type ProxyAppInfo = {
  detected: boolean;
  name: string | null;
  process_path: string | null;
  local_port: string | null;
  system_proxy: string | null;
  tun_enabled: boolean | null;
  routing_modes: string[];
  ai_rules: string[];
  message: string;
};

export type RepairGuide = {
  id: string;
  title: string;
  summary: string;
  steps: string[];
  developer_commands: string[];
};

export type TimezoneFixInfo = {
  exit_timezone: string;
  windows_timezone_id: string | null;
  windows_timezone_label: string | null;
  current_windows_timezone: string | null;
  windows_version: string;
  can_auto_fix: boolean;
  note: string;
};

export type TimezoneFixResult = {
  success: boolean;
  message: string;
  windows_timezone_id: string;
};

export type DetailRow = {
  label: string;
  value: string;
  status: CheckStatus;
};

export type DeveloperSection = {
  title: string;
  rows: DetailRow[];
};

export type BrowserProbeSource = {
  name: string;
  ip: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  timezone: string | null;
  error: string | null;
};

export type BrowserNetworkProbe = {
  exit_ip: string | null;
  ip_version: "IPv4" | "IPv6" | "unknown";
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  timezone: string | null;
  sources: BrowserProbeSource[];
};

export type GetAiOkCheckResult = {
  id: string;
  checked_at: string;
  risk_level: RiskLevel;
  beginner_summary: string;
  real_ip: string | null;
  ipv6: string | null;
  dns_servers: string[];
  exit_ip: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  org: string | null;
  asn: string | null;
  ip_version: string | null;
  browser_probe_sources: BrowserProbeSource[];
  exit_timezone: string | null;
  proxy_envs: Record<string, string>;
  system_proxy_status: CheckStatus;
  system_proxy_message: string;
  tun_vpn_status: CheckStatus;
  tun_vpn_message: string;
  proxy_app: ProxyAppInfo;
  hosting: boolean | null;
  proxy: boolean | null;
  risk_score: number | null;
  risk_query_message: string | null;
  spam_listed: boolean | null;
  spam_message: string | null;
  system_timezone: string | null;
  cli_timezone: string | null;
  timezone_matched: boolean | null;
  timezone_fix: TimezoneFixInfo | null;
  claude: ClaudeInfo;
  codex: CodexInfo;
  suggestions: string[];
  repair_guides: RepairGuide[];
  developer_details: DeveloperSection[];
};

export type HistoryEntry = {
  id: string;
  checked_at: string;
  risk_level: RiskLevel;
  beginner_summary: string;
  exit_ip: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  suggestion_count: number;
  danger_count: number;
  result: GetAiOkCheckResult;
};

export type ViewMode = "float" | "report" | "history" | "guide" | "privacy";
