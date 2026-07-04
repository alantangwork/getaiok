import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  Clipboard,
  ExternalLink,
  History,
  Info,
  Loader2,
  Minimize2,
  Pin,
  PinOff,
  RefreshCw,
  ShieldAlert,
  TerminalSquare,
  Trash2,
  X,
} from "lucide-react";
import { Image } from "@tauri-apps/api/image";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  clearCheckHistory,
  collectBrowserNetworkProbe,
  deleteCheckHistory,
  getDemoResult,
  listCheckHistory,
  runGetAiOkCheck,
} from "./api";
import logoMark from "./assets/logo-mark.svg";
import logoMarkPng from "./assets/logo-mark.png";
import type {
  BrowserProbeSource,
  CheckStatus,
  GetAiOkCheckResult,
  HistoryEntry,
  RepairGuide,
  RiskLevel,
  ViewMode,
} from "./types";

const isTauri = "__TAURI_INTERNALS__" in window;

function App() {
  const [view, setView] = useState<ViewMode>("float");
  const [checking, setChecking] = useState(false);
  const [hasConsent, setHasConsent] = useState(() => {
    return localStorage.getItem("get-ai-ok-consent") === "yes";
  });
  const [isPinned, setIsPinned] = useState(false);
  const [result, setResult] = useState<GetAiOkCheckResult>(() => getDemoResult());
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [selectedGuide, setSelectedGuide] = useState<RepairGuide | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshHistory();
  }, []);

  useEffect(() => {
    if (!isTauri) {
      return;
    }

    async function applyWindowIcon() {
      try {
        const response = await fetch(logoMarkPng);
        const bytes = new Uint8Array(await response.arrayBuffer());
        const icon = await Image.fromBytes(bytes);
        await getCurrentWindow().setIcon(icon);
      } catch (err) {
        console.warn("Failed to set window icon", err);
      }
    }

    void applyWindowIcon();
  }, []);

  async function refreshHistory() {
    if (!isTauri) {
      setHistory([
        {
          id: "demo",
          checked_at: "2026-07-02 17:20:00",
          risk_level: "medium",
          beginner_summary: "建议先处理 2 个问题，再使用 AI 工具。",
          exit_ip: "192.129.161.49",
          country: "United States",
          region: "California",
          city: "Los Angeles",
          isp: "HostPapa",
          suggestion_count: 2,
          danger_count: 0,
          result: getDemoResult(),
        },
      ]);
      return;
    }
    try {
      setHistory(await listCheckHistory());
    } catch (err) {
      console.warn(err);
    }
  }

  async function startCheck() {
    if (!hasConsent) {
      setView("privacy");
      return;
    }
    setChecking(true);
    setError(null);
    try {
      const browserProbe = await collectBrowserNetworkProbe();
      const next = isTauri ? await runGetAiOkCheck(browserProbe) : await fakeCheck();
      setResult(next);
      setSelectedGuide(next.repair_guides[0] ?? null);
      await refreshHistory();
      setView("report");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChecking(false);
    }
  }

  async function fakeCheck() {
    await new Promise((resolve) => setTimeout(resolve, 900));
    return getDemoResult();
  }

  async function acceptConsentAndCheck() {
    localStorage.setItem("get-ai-ok-consent", "yes");
    setHasConsent(true);
    setView("float");
    await startCheckWithConsent();
  }

  async function startCheckWithConsent() {
    setChecking(true);
    setError(null);
    try {
      const browserProbe = await collectBrowserNetworkProbe();
      const next = isTauri ? await runGetAiOkCheck(browserProbe) : await fakeCheck();
      setResult(next);
      setSelectedGuide(next.repair_guides[0] ?? null);
      await refreshHistory();
      setView("report");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setChecking(false);
    }
  }

  async function togglePin() {
    const next = !isPinned;
    setIsPinned(next);
    if (isTauri) {
      await getCurrentWindow().setAlwaysOnTop(next);
    }
  }

  async function minimizeWindow() {
    if (isTauri) {
      await getCurrentWindow().minimize();
    }
  }

  async function closeWindow() {
    if (isTauri) {
      await getCurrentWindow().close();
    }
  }

  async function removeHistory(id: string) {
    if (!isTauri) {
      setHistory((items) => items.filter((item) => item.id !== id));
      return;
    }
    setHistory(await deleteCheckHistory(id));
  }

  async function clearHistory() {
    if (!isTauri) {
      setHistory([]);
      return;
    }
    await clearCheckHistory();
    setHistory([]);
  }

  function openGuide(guide?: RepairGuide) {
    setSelectedGuide(guide ?? result.repair_guides[0] ?? null);
    setView("guide");
  }

  const activeGuide = selectedGuide ?? result.repair_guides[0] ?? null;

  return (
    <div className={`app-frame ${view === "float" || view === "privacy" ? "is-compact" : "is-wide"}`}>
      <TitleBar
        subtitle={viewLabel(view)}
        pinned={isPinned}
        onBack={view === "float" ? undefined : () => setView("float")}
        onTogglePin={togglePin}
        onMinimize={minimizeWindow}
        onClose={closeWindow}
      />

      {view === "float" && (
        <FloatView
          result={result}
          checking={checking}
          error={error}
          onStart={startCheck}
          onReport={() => setView("report")}
          onHistory={() => setView("history")}
          onPrivacy={() => setView("privacy")}
        />
      )}

      {view === "privacy" && (
        <PrivacyView
          checking={checking}
          onAccept={acceptConsentAndCheck}
          onCancel={() => setView("float")}
        />
      )}

      {view === "report" && (
        <ReportView
          result={result}
          checking={checking}
          onStart={startCheck}
          onHistory={() => setView("history")}
          onGuide={openGuide}
        />
      )}

      {view === "history" && (
        <HistoryView
          items={history}
          onOpen={(entry) => {
            setResult(entry.result);
            setSelectedGuide(entry.result.repair_guides[0] ?? null);
            setView("report");
          }}
          onDelete={removeHistory}
          onClear={clearHistory}
        />
      )}

      {view === "guide" && (
        <GuideView
          guide={activeGuide}
          onBack={() => setView("report")}
          onStart={startCheck}
        />
      )}
    </div>
  );
}

type TitleBarProps = {
  subtitle: string;
  pinned: boolean;
  onBack?: () => void;
  onTogglePin: () => void;
  onMinimize: () => void;
  onClose: () => void;
};

function TitleBar({
  subtitle,
  pinned,
  onBack,
  onTogglePin,
  onMinimize,
  onClose,
}: TitleBarProps) {
  function startDrag(event: React.PointerEvent<HTMLElement>) {
    if (!isTauri || event.button !== 0) {
      return;
    }
    const target = event.target as HTMLElement;
    if (target.closest("button")) {
      return;
    }
    event.preventDefault();
    void getCurrentWindow().startDragging();
  }

  function runButtonAction(
    event: React.MouseEvent<HTMLButtonElement>,
    action: () => void,
  ) {
    event.stopPropagation();
    action();
  }

  return (
    <header
      className="titlebar"
      data-tauri-drag-region
      onPointerDown={startDrag}
    >
      {onBack && (
        <button
          className="icon-button"
          type="button"
          title="返回浮窗"
          onClick={(event) => runButtonAction(event, onBack)}
        >
          <ChevronLeft size={17} />
        </button>
      )}
      <div className="brand" data-tauri-drag-region>
        <img className="brand-mark" src={logoMark} alt="" aria-hidden="true" />
        <div className="brand-copy" data-tauri-drag-region>
          <strong>get ai ok</strong>
          <span>{subtitle}</span>
        </div>
      </div>
      <div className="window-actions">
        <button
          className="icon-button"
          type="button"
          title={pinned ? "取消置顶" : "置顶"}
          onClick={(event) => runButtonAction(event, onTogglePin)}
        >
          {pinned ? <PinOff size={15} /> : <Pin size={15} />}
        </button>
        <button
          className="icon-button"
          type="button"
          title="最小化"
          onClick={(event) => runButtonAction(event, onMinimize)}
        >
          <Minimize2 size={15} />
        </button>
        <button
          className="icon-button danger"
          type="button"
          title="关闭"
          onClick={(event) => runButtonAction(event, onClose)}
        >
          <X size={16} />
        </button>
      </div>
    </header>
  );
}

type FloatViewProps = {
  result: GetAiOkCheckResult;
  checking: boolean;
  error: string | null;
  onStart: () => void;
  onReport: () => void;
  onHistory: () => void;
  onPrivacy: () => void;
};

function FloatView({
  result,
  checking,
  error,
  onStart,
  onReport,
  onHistory,
  onPrivacy,
}: FloatViewProps) {
  return (
    <main className="float-body">
      <section className="status-hero">
        <RiskBadge level={result.risk_level} />
        <h1>{checking ? "正在检测网络环境" : headline(result)}</h1>
        <p>{checking ? "通常需要 5-15 秒，单项失败不会中断整体报告。" : result.beginner_summary}</p>
      </section>

      {checking ? (
        <ProgressList />
      ) : (
        <section className="summary-list">
          <SummaryRow label="出口 IP" value={result.exit_ip ?? "未知"} status={result.hosting ? "warning" : "ok"} />
          <SummaryRow label="所在地区" value={locationText(result)} status="ok" />
          <SummaryRow label="代理状态" value={proxyText(result)} status={Object.keys(result.proxy_envs).length ? "ok" : "warning"} />
          <SummaryRow label="DNS 状态" value={result.dns_servers.length ? "已获取" : "未知"} status={result.dns_servers.length ? "ok" : "unknown"} />
          <SummaryRow label="时区状态" value={timezoneText(result)} status={result.timezone_matched === false ? "warning" : "ok"} />
        </section>
      )}

      {error && <div className="error-box">{error}</div>}

      <button className="primary-button" type="button" disabled={checking} onClick={onStart}>
        {checking ? <Loader2 className="spin" size={17} /> : <RefreshCw size={17} />}
        {checking ? "检测中" : "开始检测"}
      </button>
      <button className="link-button" type="button" onClick={onReport}>
        查看完整报告
      </button>

      <footer className="float-footer">
        <span>最近检测：{result.checked_at}</span>
        <div>
          <button type="button" onClick={onHistory}>
            历史
          </button>
          <button type="button" onClick={onPrivacy}>
            说明
          </button>
        </div>
      </footer>
    </main>
  );
}

function ProgressList() {
  return (
    <section className="progress-list">
      {["本机网络", "DNS 配置", "出口 IP", "IP 风险", "Claude Code", "Codex / OpenAI CLI"].map((item, index) => (
        <div className="progress-row" key={item}>
          {index < 2 ? <CheckCircle2 size={16} /> : index === 2 ? <Loader2 className="spin" size={16} /> : <span className="circle" />}
          <span>{item}</span>
        </div>
      ))}
    </section>
  );
}

function SummaryRow({ label, value, status }: { label: string; value: string; status: CheckStatus }) {
  return (
    <div className="summary-row">
      <span>{label}</span>
      <strong title={value}>{value}</strong>
      <i className={`dot ${statusClass(status)}`} />
    </div>
  );
}

type ReportProps = {
  result: GetAiOkCheckResult;
  checking: boolean;
  onStart: () => void;
  onHistory: () => void;
  onGuide: (guide?: RepairGuide) => void;
};

function ReportView({ result, checking, onStart, onHistory, onGuide }: ReportProps) {
  const importantGuides = result.repair_guides.slice(0, 3);

  return (
    <main className="report-body">
      <div className="toolbar">
        <div>
          <h2>当前环境：{riskLabel(result.risk_level)}</h2>
          <p>{result.beginner_summary}</p>
        </div>
        <div className="toolbar-actions">
          <button className="small-button" type="button" onClick={onHistory}>
            <History size={15} />
            历史
          </button>
          <button className="small-button primary" type="button" disabled={checking} onClick={onStart}>
            {checking ? <Loader2 className="spin" size={15} /> : <RefreshCw size={15} />}
            重新检测
          </button>
        </div>
      </div>

      <div className="overview">
        <section className="panel pad">
          <div className="panel-title">
            <h3>小白版结论</h3>
            <span>优先处理</span>
          </div>
          <div className="issue-list">
            {result.suggestions.length === 0 ? (
              <Issue status="ok" title="没有需要立即处理的问题" summary="当前网络环境看起来可以正常使用 AI 工具。" />
            ) : (
              result.suggestions.map((suggestion, index) => (
                <Issue
                  key={`${suggestion}-${index}`}
                  status={result.risk_level === "high" ? "danger" : "warning"}
                  title={issueTitle(suggestion)}
                  summary={suggestion}
                  guide={importantGuides[index]}
                  onGuide={onGuide}
                />
              ))
            )}
          </div>
        </section>

        <section className="panel pad">
          <div className="panel-title">
            <h3>检测概览</h3>
            <span>{result.checked_at}</span>
          </div>
          <div className="metric-grid">
            <Metric label="出口 IP" value={result.exit_ip ?? "未知"} />
            <Metric label="地区" value={locationText(result)} />
            <Metric label="ASN" value={result.asn ?? "未知"} />
            <Metric label="IP 版本" value={result.ip_version ?? "未知"} />
            <Metric label="IP 属性" value={ipAttributeText(result)} />
            <Metric label="风险分" value={riskScoreText(result)} />
            <Metric label="Claude" value={result.claude.message} />
            <Metric label="Codex" value={result.codex.proxy_env_present ? result.codex.message : "代理变量未设置"} />
          </div>
        </section>
      </div>

      <section className="panel pad source-panel">
        <div className="panel-title">
          <h3>多数据源位置</h3>
          <span>更接近网页检测视角</span>
        </div>
        <div className="source-grid">
          {result.browser_probe_sources.length === 0 ? (
            <div className="source-row">
              <strong>WebView 探针</strong>
              <span>未返回数据</span>
            </div>
          ) : (
            result.browser_probe_sources.map((source) => (
              <div className="source-row" key={source.name}>
                <strong>{source.name}</strong>
                <span>{sourceLocationText(source)}</span>
              </div>
            ))
          )}
        </div>
      </section>

      <section className="panel pad">
        <div className="panel-title">
          <h3>开发者详情</h3>
          <span>可复制排查信息</span>
        </div>
        <div className="developer-sections">
          {result.developer_details.map((section) => (
            <details key={section.title} open>
              <summary>{section.title}</summary>
              <table className="detail-table">
                <tbody>
                  {section.rows.map((row) => (
                    <tr key={`${section.title}-${row.label}`}>
                      <th>{row.label}</th>
                      <td>
                        <span className={`status-dot ${statusClass(row.status)}`} />
                        {row.value}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          ))}
        </div>
      </section>
    </main>
  );
}

function Issue({
  status,
  title,
  summary,
  guide,
  onGuide,
}: {
  status: "ok" | "warning" | "danger";
  title: string;
  summary: string;
  guide?: RepairGuide;
  onGuide?: (guide?: RepairGuide) => void;
}) {
  return (
    <article className={`issue ${status}`}>
      <div className="issue-header">
        <h4>{title}</h4>
        {status === "ok" ? <CheckCircle2 size={18} /> : status === "danger" ? <ShieldAlert size={18} /> : <AlertTriangle size={18} />}
      </div>
      <p>{summary}</p>
      {guide && (
        <div className="issue-actions">
          <button className="pill-button blue" type="button" onClick={() => onGuide?.(guide)}>
            查看修复向导
          </button>
        </div>
      )}
    </article>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong title={value}>{value}</strong>
    </div>
  );
}

function HistoryView({
  items,
  onOpen,
  onDelete,
  onClear,
}: {
  items: HistoryEntry[];
  onOpen: (entry: HistoryEntry) => void;
  onDelete: (id: string) => void;
  onClear: () => void;
}) {
  return (
    <main className="report-body">
      <div className="toolbar">
        <div>
          <h2>检测历史</h2>
          <p>默认保存最近 50 条，历史只保存在本机。</p>
        </div>
        <button className="small-button danger-text" type="button" onClick={onClear}>
          <Trash2 size={15} />
          清空全部
        </button>
      </div>
      <section className="panel">
        <table className="history-table">
          <thead>
            <tr>
              <th>时间</th>
              <th>结论</th>
              <th>出口 IP</th>
              <th>地区</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 ? (
              <tr>
                <td colSpan={5}>暂无历史记录。</td>
              </tr>
            ) : (
              items.map((item) => (
                <tr key={item.id}>
                  <td>{item.checked_at}</td>
                  <td>{riskLabel(item.risk_level)}</td>
                  <td>{item.exit_ip ?? "未知"}</td>
                  <td>{[item.country, item.city].filter(Boolean).join(" / ") || "未知"}</td>
                  <td className="table-actions">
                    <button type="button" onClick={() => onOpen(item)}>
                      查看
                    </button>
                    <button type="button" onClick={() => onDelete(item.id)}>
                      删除
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>
    </main>
  );
}

function GuideView({
  guide,
  onBack,
  onStart,
}: {
  guide: RepairGuide | null;
  onBack: () => void;
  onStart: () => void;
}) {
  if (!guide) {
    return (
      <main className="report-body">
        <p>当前没有需要展示的修复向导。</p>
      </main>
    );
  }

  return (
    <main className="report-body">
      <div className="toolbar">
        <div>
          <h2>修复向导：{guide.title}</h2>
          <p>{guide.summary}</p>
        </div>
        <button className="small-button" type="button" onClick={onBack}>
          返回报告
        </button>
      </div>
      <section className="panel pad guide-panel">
        <ol className="steps">
          {guide.steps.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
        {guide.developer_commands.length > 0 && (
          <>
            <div className="panel-title subtle">
              <h3>开发者命令</h3>
              <span>端口号只是示例，请按代理软件实际端口填写。</span>
            </div>
            <pre className="code-box">{guide.developer_commands.join("\n")}</pre>
          </>
        )}
        <div className="guide-actions">
          <button className="secondary-button" type="button" onClick={() => copyText(guide.developer_commands.join("\n"))}>
            <Clipboard size={16} />
            复制命令
          </button>
          <button className="primary-button" type="button" onClick={onStart}>
            <RefreshCw size={16} />
            我已处理，重新检测
          </button>
        </div>
      </section>
    </main>
  );
}

function PrivacyView({
  checking,
  onAccept,
  onCancel,
}: {
  checking: boolean;
  onAccept: () => void;
  onCancel: () => void;
}) {
  return (
    <main className="privacy-body">
      <div className="privacy-card">
        <Info size={26} />
        <h1>第三方联网检测说明</h1>
        <p>
          get ai ok 需要联网查询当前出口 IP、地区、IP 风险和滥用记录。检测过程中可能会请求第三方 IP 信息服务和风险评估服务。
        </p>
        <p>get ai ok 不会上传你的 API Key、代理密码或本地配置文件。检测历史默认只保存在本机。</p>
        <div className="privacy-actions">
          <button className="secondary-button" type="button" onClick={onCancel}>
            取消
          </button>
          <button className="primary-button" type="button" disabled={checking} onClick={onAccept}>
            {checking ? <Loader2 className="spin" size={16} /> : <ExternalLink size={16} />}
            开始检测
          </button>
        </div>
      </div>
    </main>
  );
}

function RiskBadge({ level }: { level: RiskLevel }) {
  return <div className={`risk-badge ${level}`}>● 当前环境：{riskLabel(level)}</div>;
}

function riskLabel(level: RiskLevel) {
  return level === "low" ? "低风险" : level === "high" ? "高风险" : "中风险";
}

function headline(result: GetAiOkCheckResult) {
  if (result.risk_level === "low") return "可以正常使用 AI 工具";
  if (result.risk_level === "high") return "不建议直接使用";
  return `建议先处理 ${Math.max(result.suggestions.length, 1)} 个问题`;
}

function locationText(result: GetAiOkCheckResult) {
  return [result.country, result.city].filter(Boolean).join(" / ") || "未知";
}

function proxyText(result: GetAiOkCheckResult) {
  return Object.keys(result.proxy_envs).length > 0 ? "终端代理已设置" : "终端代理未设置";
}

function timezoneText(result: GetAiOkCheckResult) {
  if (result.timezone_matched === true) return "与出口地区一致";
  if (result.timezone_matched === false) return "与出口地区不一致";
  return "无法比对";
}

function ipAttributeText(result: GetAiOkCheckResult) {
  if (result.proxy === true) return "代理 IP";
  if (result.hosting === true) return "机房 IP";
  if (result.hosting === false) return "住宅/原生 IP";
  return "未知";
}

function riskScoreText(result: GetAiOkCheckResult) {
  if (typeof result.risk_score === "number") {
    return `${result.risk_score}/100`;
  }
  return result.risk_query_message ?? "未知";
}

function sourceLocationText(source: BrowserProbeSource) {
  if (source.error) {
    return `查询失败：${source.error}`;
  }
  const location = [source.country, source.region, source.city].filter(Boolean).join(" / ");
  const network = [source.ip, source.asn, source.org ?? source.isp].filter(Boolean).join(" / ");
  return [network, location].filter(Boolean).join("  ·  ") || "无数据";
}

function statusClass(status: CheckStatus) {
  if (status === "ok") return "ok";
  if (status === "danger") return "danger";
  if (status === "warning") return "warn";
  return "unknown";
}

function issueTitle(text: string) {
  if (text.includes("时区")) return "时区和出口地区不一致";
  if (text.includes("出口 IP") || text.includes("机房") || text.includes("IP 风险")) {
    return "出口 IP 为机房/代理 IP";
  }
  if (text.includes("端点") || text.includes("Base URL")) return "第三方端点需要确认";
  if (text.includes("CLI") || text.includes("环境变量")) return "CLI 代理环境变量未设置";
  if (text.includes("代理")) return "代理配置需要关注";
  if (text.includes("DNS")) return "DNS 可能暴露地区特征";
  if (text.includes("IPv6")) return "IPv6 可能暴露真实地址";
  return "需要关注";
}

function viewLabel(view: ViewMode) {
  if (view === "report") return "完整报告";
  if (view === "history") return "检测历史";
  if (view === "guide") return "修复向导";
  if (view === "privacy") return "联网检测说明";
  return "AI 工具网络环境检测";
}

async function copyText(text: string) {
  if (!text) return;
  await navigator.clipboard.writeText(text);
}

export default App;
