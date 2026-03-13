import { useState, useEffect } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { toast } from "sonner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, Loader2, CheckCircle, XCircle, Clock,
  RefreshCw, ChevronRight, ExternalLink, AlertTriangle,
  Target, FileText, Terminal, Trash2, Play, Search, Zap
} from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

interface ScanItem {
  id: number;
  target_url: string;
  status: string;
  created_at: string;
  findings_count?: number;
}

interface ScanDetails extends ScanItem {
  findings: Finding[];
}

interface Finding {
  "template-id": string;
  info: {
    name: string;
    description?: string;
    severity: string;
    solution?: string;
  };
  url: string;
  "matched-at": string;
  evidence?: string;
}

type ScanMode = "quick" | "full" | "recon";

export default function Index() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [details, setDetails] = useState<Record<number, ScanDetails>>({});
  const [severityFilter, setSeverityFilter] = useState("all");
  const [scanMode, setScanMode] = useState<ScanMode>("recon");
  const [showLogs, setShowLogs] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);

  // Load scans list
  const loadScans = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/scans`);
      if (res.ok) setScans(await res.json());
    } catch (e) { console.error(e); }
  };

  // Load scan details
  const loadDetails = async (id: number) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/scan/${id}`);
      if (res.ok) {
        const data = await res.json();
        setDetails(prev => ({ ...prev, [id]: data }));
      }
    } catch (e) { console.error(e); }
  };

  // Load logs
  const loadLogs = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/logs`);
      if (res.ok) setLogs((await res.json()).logs || []);
    } catch (e) { console.error(e); }
  };

  // Start scan
  const handleSubmit = async () => {
    if (!target.trim()) { toast.error("Введите URL"); return; }
    let url = target.trim();
    if (!url.startsWith("http")) url = "https://" + url;
    
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/startdast`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: url, mode: scanMode })
      });
      if (res.ok) {
        const data = await res.json();
        toast.success(`Скан #${data.id} запущен!`);
        setTarget("");
        loadScans();
      } else {
        toast.error("Ошибка запуска");
      }
    } catch (e) {
      toast.error("Бэкенд недоступен");
    } finally {
      setLoading(false);
    }
  };

  // Toggle expand
  const toggle = async (id: number) => {
    if (expandedId === id) {
      setExpandedId(null);
    } else {
      setExpandedId(id);
      await loadDetails(id);
    }
  };

  // Delete scan
  const del = async (id: number) => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/scan/${id}`, { method: "DELETE" });
      if (res.ok) {
        toast.success("Удалено");
        loadScans();
        if (expandedId === id) setExpandedId(null);
      }
    } catch (e) { toast.error("Ошибка"); }
  };

  // Clear all
  const clear = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/scans`, { method: "DELETE" });
      if (res.ok) {
        setScans([]);
        setExpandedId(null);
        setDetails({});
        toast.success("Очищено");
      }
    } catch (e) { toast.error("Ошибка"); }
  };

  // Filter
  const filtered = (findings: Finding[]) => {
    if (severityFilter === "all") return findings;
    return findings.filter(f => f.info?.severity?.toLowerCase() === severityFilter.toLowerCase());
  };

  // Severity color
  const sevColor = (s: string) => {
    const c: Record<string, string> = {
      critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-500",
      low: "bg-blue-500", info: "bg-gray-400"
    };
    return c[s?.toLowerCase()] || c.info;
  };

  // Status icon
  const statusIcon = (s: string) => {
    if (s === "completed") return <CheckCircle className="h-4 w-4 text-green-500" />;
    if (s === "running") return <Loader2 className="h-4 w-4 text-yellow-500 animate-spin" />;
    if (s === "failed") return <XCircle className="h-4 w-4 text-red-500" />;
    return <Clock className="h-4 w-4 text-gray-400" />;
  };

  // Date format
  const fmtDate = (d: string) => {
    try { return new Date(d).toLocaleString("ru-RU", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }); }
    catch { return d; }
  };

  // Polling
  useEffect(() => {
    loadScans();
    const interval = setInterval(() => {
      loadScans();
      if (showLogs) loadLogs();
      if (expandedId !== null) {
        const s = scans.find(x => x.id === expandedId);
        if (s?.status === "running") loadDetails(expandedId);
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [expandedId, showLogs]);

  const modes: Record<ScanMode, { icon: any, title: string, desc: string }> = {
    quick: { icon: Zap, title: "Быстрый", desc: "Nuclei 1-2 мин" },
    full: { icon: Shield, title: "Полный", desc: "Nuclei+ZAP 10-15 мин" },
    recon: { icon: Search, title: "🔍 Recon", desc: "Разведка + эксплуатация" }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/50 backdrop-blur sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">DAST Scanner</h1>
              <p className="text-xs text-slate-400">Bug Bounty Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => window.open(`${API_BASE}/docs`, "_blank")}>
              <ExternalLink className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={loadScans}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-6">
        <Tabs defaultValue="scanner" className="space-y-6">
          <TabsList className="grid grid-cols-3 w-full max-w-md mx-auto bg-slate-800/50">
            <TabsTrigger value="scanner"><Play className="h-4 w-4 mr-2" />Сканер</TabsTrigger>
            <TabsTrigger value="results"><FileText className="h-4 w-4 mr-2" />Результаты</TabsTrigger>
            <TabsTrigger value="logs"><Terminal className="h-4 w-4 mr-2" />Логи</TabsTrigger>
          </TabsList>

          {/* Scanner */}
          <TabsContent value="scanner" className="space-y-6">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Target className="h-5 w-5 text-blue-500" /> Цель
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-2">
                  <Input
                    placeholder="https://example.com"
                    value={target}
                    onChange={e => setTarget(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && handleSubmit()}
                    className="h-12 bg-slate-800 border-slate-700 text-white flex-1"
                  />
                  <Button onClick={handleSubmit} disabled={loading} size="lg" className="h-12 px-8 bg-gradient-to-r from-blue-600 to-purple-600">
                    {loading ? <Loader2 className="h-5 w-5 animate-spin" /> : <Play className="h-5 w-5" />}
                  </Button>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setTarget("http://127.0.0.1:3000")} className="bg-slate-800">
                    <Target className="h-3 w-3 mr-1" /> Juice Shop
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Zap className="h-5 w-5 text-yellow-500" /> Режим
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-3">
                  {(Object.keys(modes) as ScanMode[]).map(m => (
                    <Button
                      key={m}
                      variant={scanMode === m ? "default" : "outline"}
                      onClick={() => setScanMode(m)}
                      className={`h-20 flex flex-col ${scanMode === m ? "bg-blue-600" : "bg-slate-800"}`}
                    >
                      {(() => { const Icon = modes[m].icon; return <Icon className="h-5 w-5 mb-1" />; })()}
                      <span className="text-xs">{modes[m].title}</span>
                      <span className="text-[10px] text-slate-400">{modes[m].desc}</span>
                    </Button>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Results */}
          <TabsContent value="results" className="space-y-6">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle className="text-white flex items-center gap-2">
                  <FileText className="h-5 w-5 text-green-500" /> История
                </CardTitle>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setShowLogs(!showLogs)}>
                    {showLogs ? "Скрыть" : "Логи"}
                  </Button>
                  <Button variant="outline" size="sm" onClick={clear} className="text-red-400">
                    <Trash2 className="h-3 w-3 mr-1" /> Очистить
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {showLogs && (
                  <Card className="bg-black/50 border-slate-700">
                    <CardContent className="pt-4">
                      <ScrollArea className="h-48">
                        <div className="font-mono text-xs text-green-400 space-y-1">
                          {logs.length ? logs.map((l, i) => <div key={i}>{l}</div>) : <div className="text-slate-500">Нет логов</div>}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                )}

                {scans.length === 0 ? (
                  <div className="py-12 text-center text-slate-400">
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-20" />
                    <p>Нет сканирований</p>
                  </div>
                ) : (
                  scans.map(scan => {
                    const d = details[scan.id];
                    const findings = d?.findings || [];
                    const f = filtered(findings);
                    
                    return (
                      <div key={scan.id} className="space-y-2">
                        <div
                          className="flex items-center justify-between rounded-lg border border-slate-700 bg-slate-800/50 px-4 py-3 cursor-pointer hover:bg-slate-800"
                          onClick={() => toggle(scan.id)}
                        >
                          <div className="flex items-center gap-3 flex-1">
                            {statusIcon(scan.status)}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="font-medium text-white truncate">{scan.target_url}</span>
                                {scan.findings_count ? (
                                  <Badge variant="destructive" className="h-5 text-xs">
                                    <AlertTriangle className="h-3 w-3 mr-1" />{scan.findings_count}
                                  </Badge>
                                ) : null}
                              </div>
                              <span className="text-xs text-slate-400">{fmtDate(scan.created_at)}</span>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button variant="ghost" size="sm" onClick={e => { e.stopPropagation(); del(scan.id); }} className="h-8 w-8 p-0 text-slate-400 hover:text-red-400">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                            <ChevronRight className={`h-4 w-4 transition-transform ${expandedId === scan.id ? "rotate-90" : ""}`} />
                          </div>
                        </div>

                        {expandedId === scan.id && (
                          <div className="ml-4 mr-2 mb-4 rounded-lg border border-slate-700 bg-slate-800/30 overflow-hidden">
                            <div className="px-4 py-2 bg-slate-900/50 border-b border-slate-700 flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {statusIcon(d?.status || "running")}
                                <span className="text-sm text-slate-300">
                                  {d?.status === "completed" ? "Завершено" : d?.status === "running" ? "Выполняется..." : "Загрузка..."}
                                </span>
                              </div>
                              <div className="text-xs text-slate-400">
                                Всего: {findings.length}
                                {severityFilter !== "all" && <span className="text-green-400"> | Показано: {f.length}</span>}
                              </div>
                            </div>

                            {/* Filter buttons */}
                            {findings.length > 0 && (
                              <div className="px-4 py-2 border-b border-slate-700 flex gap-2 flex-wrap">
                                <Button variant={severityFilter === "all" ? "default" : "outline"} size="sm" className="h-7 text-xs bg-slate-800" onClick={() => setSeverityFilter("all")}>Все</Button>
                                {["critical", "high", "medium", "low", "info"].map(s => (
                                  <Button key={s} variant={severityFilter === s ? "default" : "outline"} size="sm" className={`h-7 text-xs ${sevColor(s)}`} onClick={() => setSeverityFilter(s)}>{s.toUpperCase()}</Button>
                                ))}
                              </div>
                            )}

                            {/* Findings list */}
                            <div className="max-h-[600px] overflow-y-auto">
                              {findings.length === 0 ? (
                                <div className="p-8 text-center text-slate-400">
                                  {d?.status === "running" ? <div className="flex items-center justify-center gap-2"><Loader2 className="h-4 w-4 animate-spin" />Сканирование...</div> : "Нет уязвимостей"}
                                </div>
                              ) : f.length === 0 ? (
                                <div className="p-8 text-center text-slate-400">Нет уязвимостей с фильтром "{severityFilter}"</div>
                              ) : (
                                <div className="divide-y divide-slate-700">
                                  {f.map((x, i) => (
                                    <div key={i} className="p-4 border-l-4" style={{
                                      borderColor: x.info?.severity === "critical" ? "#dc2626" : x.info?.severity === "high" ? "#f97316" : x.info?.severity === "medium" ? "#eab308" : x.info?.severity === "low" ? "#3b82f6" : "#9ca3af",
                                      backgroundColor: x.info?.severity === "critical" ? "rgba(220,38,38,0.1)" : x.info?.severity === "high" ? "rgba(249,115,22,0.1)" : x.info?.severity === "medium" ? "rgba(234,179,8,0.1)" : x.info?.severity === "low" ? "rgba(59,130,246,0.1)" : "rgba(156,163,175,0.1)"
                                    }}>
                                      <div className="flex items-center gap-2 mb-2">
                                        <Badge className={`${sevColor(x.info?.severity)} text-white text-xs`}>{x.info?.severity?.toUpperCase()}</Badge>
                                        <span className="font-medium text-white">{x.info?.name}</span>
                                      </div>
                                      {x.info?.description && <p className="text-sm text-slate-400 mb-2">{x.info.description}</p>}
                                      <div className="text-xs text-slate-500 flex items-center gap-1">
                                        <span className="truncate">{x["matched-at"]}</span>
                                      </div>
                                      {x.evidence && <div className="mt-2"><span className="text-slate-500">Evidence: </span><code className="bg-slate-800 px-2 py-1 rounded text-green-400 text-xs">{x.evidence}</code></div>}
                                      {x.info?.solution && <div className="mt-2 text-xs text-slate-300"><span className="text-slate-500">Solution: </span>{x.info.solution}</div>}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* Logs */}
          <TabsContent value="logs">
            <Card className="bg-slate-900/50 border-slate-800">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <Terminal className="h-5 w-5 text-green-500" /> Логи
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-96">
                  <div className="font-mono text-xs text-green-400 space-y-1 bg-black/50 p-4 rounded">
                    {logs.length ? logs.map((l, i) => <div key={i}>{l}</div>) : <div className="text-slate-500">Нет логов</div>}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
