use chrono::Local;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env,
    fs,
    net::{IpAddr, UdpSocket},
    path::PathBuf,
    process::Command,
    time::Duration,
};
use tauri::{AppHandle, Manager};
use url::Url;
use uuid::Uuid;

const HISTORY_LIMIT: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warning,
    Danger,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeInfo {
    pub installed: Option<bool>,
    pub base_url: Option<String>,
    pub endpoint_status: CheckStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodexInfo {
    pub openai_api_key_present: Option<bool>,
    pub openai_base_url: Option<String>,
    pub proxy_env_present: bool,
    pub endpoint_status: CheckStatus,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairGuide {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub steps: Vec<String>,
    pub developer_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailRow {
    pub label: String,
    pub value: String,
    pub status: CheckStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeveloperSection {
    pub title: String,
    pub rows: Vec<DetailRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProbeSource {
    pub name: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub timezone: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserNetworkProbe {
    pub exit_ip: Option<String>,
    pub ip_version: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub timezone: Option<String>,
    pub sources: Vec<BrowserProbeSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAiOkCheckResult {
    pub id: String,
    pub checked_at: String,
    pub risk_level: RiskLevel,
    pub beginner_summary: String,
    pub real_ip: Option<String>,
    pub ipv6: Option<String>,
    pub dns_servers: Vec<String>,
    pub exit_ip: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub asn: Option<String>,
    pub ip_version: Option<String>,
    pub browser_probe_sources: Vec<BrowserProbeSource>,
    pub exit_timezone: Option<String>,
    pub proxy_envs: BTreeMap<String, String>,
    pub system_proxy_status: CheckStatus,
    pub system_proxy_message: String,
    pub tun_vpn_status: CheckStatus,
    pub tun_vpn_message: String,
    pub hosting: Option<bool>,
    pub proxy: Option<bool>,
    pub risk_score: Option<u8>,
    pub risk_query_message: Option<String>,
    pub spam_listed: Option<bool>,
    pub spam_message: Option<String>,
    pub system_timezone: Option<String>,
    pub cli_timezone: Option<String>,
    pub timezone_matched: Option<bool>,
    pub claude: ClaudeInfo,
    pub codex: CodexInfo,
    pub suggestions: Vec<String>,
    pub repair_guides: Vec<RepairGuide>,
    pub developer_details: Vec<DeveloperSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub checked_at: String,
    pub risk_level: RiskLevel,
    pub beginner_summary: String,
    pub exit_ip: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub suggestion_count: usize,
    pub danger_count: usize,
    pub result: GetAiOkCheckResult,
}

#[tauri::command]
pub fn run_get_ai_ok_check(
    app: AppHandle,
    browser_probe: Option<BrowserNetworkProbe>,
) -> Result<GetAiOkCheckResult, String> {
    let result = build_check_result(browser_probe);
    append_history(&app, &result)?;
    Ok(result)
}

#[tauri::command]
pub fn list_check_history(app: AppHandle) -> Result<Vec<HistoryEntry>, String> {
    read_history(&app)
}

#[tauri::command]
pub fn delete_check_history(app: AppHandle, id: String) -> Result<Vec<HistoryEntry>, String> {
    let mut items = read_history(&app)?;
    items.retain(|item| item.id != id);
    write_history(&app, &items)?;
    Ok(items)
}

#[tauri::command]
pub fn clear_check_history(app: AppHandle) -> Result<(), String> {
    write_history(&app, &[])
}

fn build_check_result(browser_probe: Option<BrowserNetworkProbe>) -> GetAiOkCheckResult {
    let client = Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("get-ai-ok/0.1")
        .build()
        .unwrap_or_else(|_| Client::new());

    let real_ip = get_real_public_ip(&client);
    let ipv6 = get_ipv6();
    let dns_servers = get_dns_servers();
    let public_info = get_public_info(&client);
    let exit_ip = browser_probe
        .as_ref()
        .and_then(|probe| probe.exit_ip.clone())
        .or_else(|| {
            public_info
                .as_ref()
                .and_then(|v| v.get("query"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    let hosting = public_info
        .as_ref()
        .and_then(|v| v.get("hosting"))
        .and_then(Value::as_bool)
        .or_else(|| infer_hosting_from_probe(&browser_probe));
    let proxy = public_info
        .as_ref()
        .and_then(|v| v.get("proxy"))
        .and_then(Value::as_bool);

    let (risk_score, risk_query_message) = if hosting == Some(true) || proxy == Some(true) {
        query_ip_risk(&client, exit_ip.as_deref())
    } else {
        (None, None)
    };
    let (spam_listed, spam_message) = if hosting == Some(true) || proxy == Some(true) {
        query_spam_record(&client, exit_ip.as_deref())
    } else {
        (None, None)
    };

    let proxy_envs = get_proxy_envs();
    let (system_proxy_status, system_proxy_message) = get_system_proxy_status();
    let (tun_vpn_status, tun_vpn_message) = get_tun_vpn_status();
    let system_timezone = get_system_timezone();
    let cli_timezone = env::var("TZ").ok().or_else(|| system_timezone.clone());
    let exit_timezone = browser_probe
        .as_ref()
        .and_then(|probe| probe.timezone.clone())
        .or_else(|| {
            public_info
                .as_ref()
                .and_then(|v| v.get("timezone"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    let timezone_matched = compare_timezone(cli_timezone.as_deref(), exit_timezone.as_deref());
    let claude = get_claude_info();
    let codex = get_codex_info(!proxy_envs.is_empty());

    let mut suggestions = Vec::new();
    let mut guides = Vec::new();
    let mut danger_count = 0usize;

    if ipv6.is_some() {
        danger_count += 1;
        suggestions.push("IPv6 已启用，可能绕过代理暴露真实地址。".to_string());
        guides.push(ipv6_guide());
    }

    if dns_has_cn(&dns_servers) {
        suggestions.push("DNS 使用国内服务商，可能暴露真实地区特征。".to_string());
        guides.push(dns_guide());
    }

    if proxy_envs.is_empty() {
        suggestions.push("终端代理未设置，Claude/Codex 可能不会走代理。".to_string());
        guides.push(proxy_env_guide());
    }

    if matches!(timezone_matched, Some(false)) {
        suggestions.push("本机时区与出口 IP 所在时区不一致。".to_string());
        guides.push(timezone_guide(exit_timezone.clone()));
    }

    if hosting == Some(true) || proxy == Some(true) {
        suggestions.push("当前出口 IP 可能是机房或代理 IP，建议关注风险。".to_string());
        guides.push(ip_risk_guide());
    }

    if risk_score.is_some_and(|score| score >= 70) {
        danger_count += 1;
    }

    if matches!(claude.endpoint_status, CheckStatus::Danger) {
        danger_count += 1;
        suggestions.push("Claude 使用了非官方端点，请确认端点来源可信。".to_string());
        guides.push(endpoint_guide("Claude Code"));
    }

    if matches!(codex.endpoint_status, CheckStatus::Danger) {
        danger_count += 1;
        suggestions.push("Codex/OpenAI CLI 使用了非官方 Base URL，请确认端点来源可信。".to_string());
        guides.push(endpoint_guide("Codex / OpenAI CLI"));
    }

    let risk_level = if danger_count > 0 || risk_score.is_some_and(|score| score >= 70) {
        RiskLevel::High
    } else if !suggestions.is_empty()
        || risk_score.is_some_and(|score| score >= 30)
        || spam_listed == Some(true)
    {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    let beginner_summary = match risk_level {
        RiskLevel::Low => "当前环境可以正常使用 AI 工具。".to_string(),
        RiskLevel::Medium => format!("建议先处理 {} 个问题，再使用 AI 工具。", suggestions.len()),
        RiskLevel::High => "当前环境高风险，不建议直接使用 AI 工具。".to_string(),
    };

    let mut result = GetAiOkCheckResult {
        id: Uuid::new_v4().to_string(),
        checked_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        risk_level,
        beginner_summary,
        real_ip,
        ipv6,
        dns_servers,
        exit_ip,
        country: probe_field(&browser_probe, |probe| probe.country.clone())
            .or_else(|| field(&public_info, "country")),
        region: probe_field(&browser_probe, |probe| probe.region.clone())
            .or_else(|| field(&public_info, "regionName")),
        city: probe_field(&browser_probe, |probe| probe.city.clone())
            .or_else(|| field(&public_info, "city")),
        isp: probe_field(&browser_probe, |probe| probe.isp.clone())
            .or_else(|| field(&public_info, "isp")),
        org: probe_field(&browser_probe, |probe| probe.org.clone())
            .or_else(|| field(&public_info, "org")),
        asn: probe_field(&browser_probe, |probe| probe.asn.clone()),
        ip_version: probe_field(&browser_probe, |probe| Some(probe.ip_version.clone())),
        browser_probe_sources: browser_probe
            .as_ref()
            .map(|probe| probe.sources.clone())
            .unwrap_or_default(),
        exit_timezone,
        proxy_envs,
        system_proxy_status,
        system_proxy_message,
        tun_vpn_status,
        tun_vpn_message,
        hosting,
        proxy,
        risk_score,
        risk_query_message,
        spam_listed,
        spam_message,
        system_timezone,
        cli_timezone,
        timezone_matched,
        claude,
        codex,
        suggestions,
        repair_guides: guides,
        developer_details: Vec::new(),
    };
    result.developer_details = developer_details(&result);
    result
}

fn field(public_info: &Option<Value>, name: &str) -> Option<String> {
    public_info
        .as_ref()
        .and_then(|v| v.get(name))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn probe_field(
    probe: &Option<BrowserNetworkProbe>,
    getter: impl FnOnce(&BrowserNetworkProbe) -> Option<String>,
) -> Option<String> {
    probe.as_ref().and_then(getter).filter(|value| !value.trim().is_empty())
}

fn infer_hosting_from_probe(probe: &Option<BrowserNetworkProbe>) -> Option<bool> {
    let probe = probe.as_ref()?;
    let text = [
        probe.isp.clone(),
        probe.org.clone(),
        probe.asn.clone(),
        Some(probe
            .sources
            .iter()
            .filter_map(|source| source.org.clone().or_else(|| source.isp.clone()))
            .collect::<Vec<_>>()
            .join(" ")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ")
    .to_lowercase();
    if text.is_empty() {
        return None;
    }
    let datacenter_hints = [
        "racknerd",
        "hostpapa",
        "colo",
        "colocation",
        "data center",
        "datacenter",
        "cloud",
        "hosting",
        "server",
        "vps",
        "digitalocean",
        "linode",
        "vultr",
        "hetzner",
        "ovh",
        "amazon",
        "aws",
        "google",
        "microsoft",
        "azure",
        "oracle",
        "cloudflare",
        "tencent",
        "alibaba",
    ];
    if datacenter_hints.iter().any(|hint| text.contains(hint)) {
        Some(true)
    } else {
        None
    }
}

fn get_real_public_ip(client: &Client) -> Option<String> {
    for url in ["http://ip.3322.net", "https://4.ipw.cn"] {
        if let Ok(text) = client.get(url).send().and_then(|r| r.text()) {
            let value = text.trim();
            if value.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv4()) {
                return Some(value.to_string());
            }
        }
    }
    if let Ok(text) = client.get("https://myip.ipip.net").send().and_then(|r| r.text()) {
        for part in text.split_whitespace() {
            let trimmed = part.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
            if trimmed.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv4()) {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn get_ipv6() -> Option<String> {
    let socket = UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:80").ok()?;
    let addr = socket.local_addr().ok()?;
    match addr.ip() {
        IpAddr::V6(ip) if !ip.is_unspecified() => Some(ip.to_string()),
        _ => None,
    }
}

fn get_dns_servers() -> Vec<String> {
    let output = powershell(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses",
        5,
    );
    let mut servers = Vec::new();
    if let Some(out) = output {
        for line in out.lines() {
            let ip = line.trim();
            if ip.parse::<IpAddr>().is_ok() && !servers.iter().any(|item| item == ip) {
                servers.push(ip.to_string());
            }
        }
    }
    servers
}

fn get_public_info(client: &Client) -> Option<Value> {
    client
        .get("http://ip-api.com/json/")
        .query(&[(
            "fields",
            "status,message,country,regionName,city,isp,org,proxy,hosting,query,timezone",
        )])
        .send()
        .ok()?
        .json::<Value>()
        .ok()
        .filter(|v| v.get("status").and_then(Value::as_str) == Some("success"))
}

fn query_ip_risk(client: &Client, ip: Option<&str>) -> (Option<u8>, Option<String>) {
    let Some(ip) = ip else {
        return (None, Some("缺少出口 IP，无法查询风险分。".to_string()));
    };
    let url = format!("https://proxycheck.io/v2/{ip}");
    match client
        .get(url)
        .query(&[("risk", "1"), ("vpn", "1"), ("asn", "1")])
        .send()
        .and_then(|r| r.json::<Value>())
    {
        Ok(data) => {
            let score = data
                .get(ip)
                .and_then(|v| v.get("risk"))
                .and_then(Value::as_u64)
                .and_then(|v| u8::try_from(v).ok());
            (score, score.map(|v| format!("风险分 {v}/100")))
        }
        Err(err) => (None, Some(format!("风险查询失败：{err}"))),
    }
}

fn query_spam_record(client: &Client, ip: Option<&str>) -> (Option<bool>, Option<String>) {
    let Some(ip) = ip else {
        return (None, Some("缺少出口 IP，无法查询滥用记录。".to_string()));
    };
    match client
        .get("https://api.stopforumspam.org/api")
        .query(&[("json", "1"), ("ip", ip)])
        .send()
        .and_then(|r| r.json::<Value>())
    {
        Ok(data) => {
            let appears = data
                .get("ip")
                .and_then(|v| v.get("appears"))
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0;
            let message = if appears {
                "发现滥用记录".to_string()
            } else {
                "未发现滥用记录".to_string()
            };
            (Some(appears), Some(message))
        }
        Err(err) => (None, Some(format!("滥用记录查询失败：{err}"))),
    }
}

fn get_proxy_envs() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        if let Ok(value) = env::var(key) {
            if !value.trim().is_empty() {
                map.insert(key.to_uppercase(), value);
            }
        }
    }
    map
}

fn get_system_proxy_status() -> (CheckStatus, String) {
    let script = r#"
$p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($p.ProxyEnable -eq 1) { "enabled:$($p.ProxyServer)" } else { "disabled" }
"#;
    match powershell(script, 4).map(|s| s.trim().to_string()) {
        Some(value) if value.starts_with("enabled:") => {
            (CheckStatus::Ok, value.replacen("enabled:", "已开启：", 1))
        }
        Some(_) => (CheckStatus::Warning, "系统代理未开启".to_string()),
        None => (CheckStatus::Unknown, "系统代理检测失败".to_string()),
    }
}

fn get_tun_vpn_status() -> (CheckStatus, String) {
    let script = r#"
Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
  "$($_.Name) $($_.InterfaceDescription)"
}
"#;
    let hints = ["tun", "tap", "wintun", "wireguard", "clash", "mihomo", "tailscale", "zerotier"];
    match powershell(script, 5) {
        Some(output) => {
            let lower = output.to_lowercase();
            if hints.iter().any(|hint| lower.contains(hint)) {
                (CheckStatus::Ok, "疑似检测到 TUN/VPN 网卡".to_string())
            } else {
                (CheckStatus::Warning, "未检测到明显 TUN/VPN 网卡".to_string())
            }
        }
        None => (CheckStatus::Unknown, "TUN/VPN 检测失败".to_string()),
    }
}

fn get_system_timezone() -> Option<String> {
    powershell("[System.TimeZoneInfo]::Local.Id", 3).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn compare_timezone(local: Option<&str>, exit: Option<&str>) -> Option<bool> {
    let local = local?;
    let exit = exit?;
    if local == exit {
        return Some(true);
    }
    if local == "China Standard Time" && exit.starts_with("Asia/Shanghai") {
        return Some(true);
    }
    Some(false)
}

fn get_claude_info() -> ClaudeInfo {
    let shell_base = env::var("ANTHROPIC_BASE_URL").ok();
    let config_base = read_claude_base_url_from_settings();
    let base_url = shell_base.or(config_base);
    let installed = Some(
        env::var("CLAUDE_CONFIG_DIR")
            .ok()
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|home| home.join(".claude")))
            .is_some_and(|path| path.exists())
            || home_dir().is_some_and(|home| home.join(".claude.json").exists())
            || command_exists("claude"),
    );

    match base_url {
        None => ClaudeInfo {
            installed,
            base_url: None,
            endpoint_status: CheckStatus::Ok,
            message: "官方直连（未设置 ANTHROPIC_BASE_URL）".to_string(),
        },
        Some(url) if is_official_anthropic(&url) => ClaudeInfo {
            installed,
            base_url: Some(url),
            endpoint_status: CheckStatus::Ok,
            message: "官方端点 api.anthropic.com".to_string(),
        },
        Some(url) => ClaudeInfo {
            installed,
            base_url: Some(mask_url(&url)),
            endpoint_status: CheckStatus::Danger,
            message: "检测到非官方 Claude 端点".to_string(),
        },
    }
}

fn get_codex_info(proxy_env_present: bool) -> CodexInfo {
    let key_present = env::var("OPENAI_API_KEY").ok().is_some_and(|v| !v.trim().is_empty());
    let base_url = env::var("OPENAI_BASE_URL")
        .ok()
        .or_else(|| env::var("OPENAI_API_BASE").ok());
    let (endpoint_status, message) = match &base_url {
        None => (CheckStatus::Ok, "未设置 OpenAI Base URL，默认官方端点".to_string()),
        Some(url) if is_official_openai(url) => (CheckStatus::Ok, "官方 OpenAI 端点".to_string()),
        Some(_) => (CheckStatus::Danger, "检测到非官方 OpenAI Base URL".to_string()),
    };

    CodexInfo {
        openai_api_key_present: Some(key_present),
        openai_base_url: base_url.map(|url| mask_url(&url)),
        proxy_env_present,
        endpoint_status,
        message,
    }
}

fn read_claude_base_url_from_settings() -> Option<String> {
    let cfg = env::var("CLAUDE_CONFIG_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".claude")))?;
    for name in ["settings.json", "settings.local.json"] {
        let path = cfg.join(name);
        let text = fs::read_to_string(path).ok()?;
        let json: Value = serde_json::from_str(&text).ok()?;
        if let Some(value) = json
            .get("env")
            .and_then(|v| v.get("ANTHROPIC_BASE_URL"))
            .and_then(Value::as_str)
        {
            return Some(value.to_string());
        }
    }
    None
}

fn is_official_anthropic(raw: &str) -> bool {
    Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .is_some_and(|host| host.eq_ignore_ascii_case("api.anthropic.com"))
}

fn is_official_openai(raw: &str) -> bool {
    Url::parse(raw)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .is_some_and(|host| {
            host.eq_ignore_ascii_case("api.openai.com")
                || host.eq_ignore_ascii_case("api.chatgpt.com")
        })
}

fn mask_url(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(url) => url.host_str().unwrap_or(raw).to_string(),
        Err(_) => raw.to_string(),
    }
}

fn command_exists(name: &str) -> bool {
    Command::new("where")
        .arg(name)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn powershell(script: &str, timeout_seconds: u64) -> Option<String> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else if timeout_seconds == 0 {
        None
    } else {
        None
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("USERPROFILE").map(PathBuf::from)
}

fn dns_has_cn(servers: &[String]) -> bool {
    servers.iter().any(|dns| {
        matches!(
            dns.as_str(),
            "223.5.5.5"
                | "223.6.6.6"
                | "119.29.29.29"
                | "182.254.116.116"
                | "114.114.114.114"
                | "114.114.115.115"
                | "180.76.76.76"
                | "1.2.4.8"
                | "210.2.4.8"
        )
    })
}

fn proxy_env_guide() -> RepairGuide {
    RepairGuide {
        id: "proxy-env".to_string(),
        title: "终端代理可能未设置".to_string(),
        summary: "Claude Code、Codex 这类命令行工具，不一定会自动使用系统代理。".to_string(),
        steps: vec![
            "打开你的代理软件。".to_string(),
            "找到本地 HTTP 或 SOCKS5 端口。".to_string(),
            "在 PowerShell 中设置代理环境变量。".to_string(),
            "重新运行 get ai ok 检测。".to_string(),
        ],
        developer_commands: vec![
            r#"$env:HTTP_PROXY="http://127.0.0.1:7890""#.to_string(),
            r#"$env:HTTPS_PROXY="http://127.0.0.1:7890""#.to_string(),
            r#"$env:ALL_PROXY="socks5://127.0.0.1:7891""#.to_string(),
        ],
    }
}

fn ipv6_guide() -> RepairGuide {
    RepairGuide {
        id: "ipv6".to_string(),
        title: "关闭 IPv6".to_string(),
        summary: "部分代理只处理 IPv4，IPv6 可能绕过代理暴露真实地址。".to_string(),
        steps: vec![
            "打开 Windows 设置。".to_string(),
            "进入网络和 Internet，打开高级网络设置。".to_string(),
            "进入当前网卡属性，取消勾选 Internet 协议版本 6。".to_string(),
            "重新运行检测。".to_string(),
        ],
        developer_commands: Vec::new(),
    }
}

fn dns_guide() -> RepairGuide {
    RepairGuide {
        id: "dns".to_string(),
        title: "调整 DNS 防泄露设置".to_string(),
        summary: "国内 DNS 可能导致地区特征和出口 IP 不一致。".to_string(),
        steps: vec![
            "打开代理软件的 DNS 设置。".to_string(),
            "启用远程 DNS 或防泄露 DNS。".to_string(),
            "避免在 AI 工具流量中使用国内 DNS 解析。".to_string(),
        ],
        developer_commands: Vec::new(),
    }
}

fn timezone_guide(exit_timezone: Option<String>) -> RepairGuide {
    RepairGuide {
        id: "timezone".to_string(),
        title: "调整 CLI 时区".to_string(),
        summary: "本机时区与出口 IP 所在地区不一致，可能形成异常环境特征。".to_string(),
        steps: vec![
            "确认当前出口 IP 所在时区。".to_string(),
            "仅在当前终端临时设置 TZ，避免影响整个系统。".to_string(),
            "重新运行检测确认时区一致性。".to_string(),
        ],
        developer_commands: vec![format!(
            r#"$env:TZ="{}""#,
            exit_timezone.unwrap_or_else(|| "America/Los_Angeles".to_string())
        )],
    }
}

fn ip_risk_guide() -> RepairGuide {
    RepairGuide {
        id: "ip-risk".to_string(),
        title: "更换更干净的出口节点".to_string(),
        summary: "机房 IP 不一定不可用，但更容易被风控系统关注。".to_string(),
        steps: vec![
            "优先选择风险分低、滥用记录少的节点。".to_string(),
            "避免长期使用被大量共享的低质量机房节点。".to_string(),
            "更换节点后重新检测。".to_string(),
        ],
        developer_commands: Vec::new(),
    }
}

fn endpoint_guide(name: &str) -> RepairGuide {
    RepairGuide {
        id: format!("endpoint-{}", name.replace(' ', "-").to_lowercase()),
        title: format!("确认 {name} 端点来源"),
        summary: "第三方中转端点可能带来数据泄露、稳定性和账号风险。".to_string(),
        steps: vec![
            "确认 Base URL 或代理端点来自可信服务。".to_string(),
            "不要在不可信端点中使用真实 API Key。".to_string(),
            "如果不确定，改回官方端点或可信服务。".to_string(),
        ],
        developer_commands: Vec::new(),
    }
}

fn developer_details(result: &GetAiOkCheckResult) -> Vec<DeveloperSection> {
    vec![
        DeveloperSection {
            title: "基础网络".to_string(),
            rows: vec![
                row("真实 IP", opt(&result.real_ip), CheckStatus::Unknown),
                row("IPv6", opt(&result.ipv6), if result.ipv6.is_some() { CheckStatus::Warning } else { CheckStatus::Ok }),
                row("DNS", list(&result.dns_servers), if dns_has_cn(&result.dns_servers) { CheckStatus::Warning } else { CheckStatus::Ok }),
            ],
        },
        DeveloperSection {
            title: "出口信息".to_string(),
            rows: vec![
                row("出口 IP", opt(&result.exit_ip), CheckStatus::Unknown),
                row("IP 版本", opt(&result.ip_version), CheckStatus::Unknown),
                row("ASN", opt(&result.asn), CheckStatus::Unknown),
                row("地区", format!("{} / {}", opt(&result.country), opt(&result.region)), CheckStatus::Unknown),
                row("ISP / 组织", format!("{} / {}", opt(&result.isp), opt(&result.org)), CheckStatus::Unknown),
                row("机房 IP", bool_text(result.hosting), if result.hosting == Some(true) { CheckStatus::Warning } else { CheckStatus::Ok }),
                row("代理标记", bool_text(result.proxy), if result.proxy == Some(true) { CheckStatus::Warning } else { CheckStatus::Ok }),
            ],
        },
        DeveloperSection {
            title: "WebView 多源出口".to_string(),
            rows: browser_probe_rows(result),
        },
        DeveloperSection {
            title: "代理环境".to_string(),
            rows: vec![
                row("环境变量", if result.proxy_envs.is_empty() { "未设置".to_string() } else { format!("已设置 {} 项", result.proxy_envs.len()) }, if result.proxy_envs.is_empty() { CheckStatus::Warning } else { CheckStatus::Ok }),
                row("系统代理", result.system_proxy_message.clone(), result.system_proxy_status.clone()),
                row("TUN/VPN", result.tun_vpn_message.clone(), result.tun_vpn_status.clone()),
            ],
        },
        DeveloperSection {
            title: "Claude / Codex".to_string(),
            rows: vec![
                row("Claude", result.claude.message.clone(), result.claude.endpoint_status.clone()),
                row("Codex", result.codex.message.clone(), result.codex.endpoint_status.clone()),
                row("OPENAI_API_KEY", if result.codex.openai_api_key_present == Some(true) { "已设置".to_string() } else { "未设置".to_string() }, CheckStatus::Unknown),
            ],
        },
    ]
}

fn row(label: &str, value: String, status: CheckStatus) -> DetailRow {
    DetailRow {
        label: label.to_string(),
        value,
        status,
    }
}

fn browser_probe_rows(result: &GetAiOkCheckResult) -> Vec<DetailRow> {
    if result.browser_probe_sources.is_empty() {
        return vec![row(
            "WebView 探针",
            "未返回数据".to_string(),
            CheckStatus::Unknown,
        )];
    }
    result
        .browser_probe_sources
        .iter()
        .map(|source| {
            let status = if source.ip.is_some() {
                CheckStatus::Ok
            } else {
                CheckStatus::Warning
            };
            let value = if let Some(error) = &source.error {
                format!("查询失败：{error}")
            } else {
                [
                    source.ip.clone(),
                    source.asn.clone(),
                    source.country.clone(),
                    source.region.clone(),
                    source.city.clone(),
                    source.org.clone().or_else(|| source.isp.clone()),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" / ")
            };
            row(&source.name, value, status)
        })
        .collect()
}

fn opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "未知".to_string())
}

fn list(values: &[String]) -> String {
    if values.is_empty() {
        "未知".to_string()
    } else {
        values.join(", ")
    }
}

fn bool_text(value: Option<bool>) -> String {
    match value {
        Some(true) => "是".to_string(),
        Some(false) => "否".to_string(),
        None => "未知".to_string(),
    }
}

fn history_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("无法获取应用数据目录：{err}"))?;
    fs::create_dir_all(&dir).map_err(|err| format!("无法创建应用数据目录：{err}"))?;
    Ok(dir.join("history.json"))
}

fn read_history(app: &AppHandle) -> Result<Vec<HistoryEntry>, String> {
    let path = history_path(app)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|err| format!("无法读取历史记录：{err}"))?;
    serde_json::from_str(&text).map_err(|err| format!("历史记录格式错误：{err}"))
}

fn write_history(app: &AppHandle, items: &[HistoryEntry]) -> Result<(), String> {
    let path = history_path(app)?;
    let text = serde_json::to_string_pretty(items).map_err(|err| format!("无法序列化历史记录：{err}"))?;
    fs::write(path, text).map_err(|err| format!("无法写入历史记录：{err}"))
}

fn append_history(app: &AppHandle, result: &GetAiOkCheckResult) -> Result<(), String> {
    let mut items = read_history(app)?;
    items.insert(0, HistoryEntry::from_result(result.clone()));
    items.truncate(HISTORY_LIMIT);
    write_history(app, &items)
}

impl HistoryEntry {
    fn from_result(result: GetAiOkCheckResult) -> Self {
        let danger_count = result
            .developer_details
            .iter()
            .flat_map(|section| section.rows.iter())
            .filter(|row| matches!(row.status, CheckStatus::Danger))
            .count();
        Self {
            id: result.id.clone(),
            checked_at: result.checked_at.clone(),
            risk_level: result.risk_level.clone(),
            beginner_summary: result.beginner_summary.clone(),
            exit_ip: result.exit_ip.clone(),
            country: result.country.clone(),
            region: result.region.clone(),
            city: result.city.clone(),
            isp: result.isp.clone(),
            suggestion_count: result.suggestions.len(),
            danger_count,
            result,
        }
    }
}
