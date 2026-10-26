import { useEffect, useRef, useState } from 'react';
import { api, TENANT_ID } from '../api/client';
import { getEnterpriseAuthSession } from '../auth';
import { readEmployeeScope } from '../lib/agent-scope-storage';

type Tracking = { clientRequestId: string; taskId?: string };
type Receipt = { success?: boolean; data?: { accepted?: boolean; task_id?: string } };
type Task = { id: string; status: string; result?: unknown; error?: unknown };
const stopped = new Set(['completed', 'failed', 'cancelled', 'expired', 'outcome_unknown', 'tracking_blocked']);
function currentScope() { try { return readEmployeeScope(); } catch { return ''; } }

/** A lost POST is reconciled by GET using its durable request ID, never replayed. */
export function useToolTest(toolId: string) {
  const auth = getEnterpriseAuthSession();
  const userId = auth?.user.id || 'anonymous';
  const agentId = currentScope();
  const storageKey = JSON.stringify(['staffdeck-tool-test-v2', TENANT_ID, userId, agentId, toolId]);
  const [result, setResult] = useState<unknown>(null);
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [queryError, setQueryError] = useState('');
  const [tracking, setTracking] = useState<Tracking | null>(null);
  const [queryVersion, setQueryVersion] = useState(0);
  const lock = useRef(false);
  const generation = useRef(0);
  const postController = useRef<AbortController | null>(null);
  const activeScope = useRef(storageKey);
  activeScope.current = storageKey;
  const persist = (value: Tracking) => localStorage.setItem(storageKey, JSON.stringify(value));


  async function enrichTracking(value: Tracking, epoch: number) {
    let accepted = false;
    let foreign: Tracking | null = null;
    try {
      if (!navigator.locks) throw new Error('browser lock unavailable');
      await navigator.locks.request(storageKey, () => {
        if (activeScope.current !== storageKey || generation.current !== epoch) return;
        const saved = JSON.parse(localStorage.getItem(storageKey) || 'null') as Tracking | null;
        if (saved?.clientRequestId !== value.clientRequestId) { foreign = saved; return; }
        // Even if enrichment hits quota, the original durable request ID remains.
        try { persist(value); } catch { /* Never replace the claim or issue a new POST. */ }
        accepted = true;
      });
    } catch { /* Missing/corrupt durable state cannot authorize another call. */ }
    if (!accepted && activeScope.current === storageKey && generation.current === epoch) {
      setBusy(true); setStatus('reconciling'); setTracking(foreign);
      setQueryError('调用记录已变化或无法核实，仅查询现有调用；未创建新调用。');
    }
    return accepted;
  }

  useEffect(() => {
    generation.current += 1; lock.current = false;
    setResult(null); setStatus(''); setBusy(false); setTracking(null); setQueryError('');
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) {
        const saved = JSON.parse(raw) as Tracking;
        if (!/^[a-z0-9-]{1,128}$/.test(saved.clientRequestId)) throw new Error('invalid record');
        lock.current = true; setBusy(true); setStatus('reconciling'); setTracking(saved);
      }
    } catch {
      lock.current = true; setBusy(true); setStatus('tracking_blocked');
      setQueryError('无法读取已保存的调用记录，不能安全重试；请先核实原调用。');
    }
    return () => { generation.current += 1; postController.current?.abort(); };
  }, [storageKey]);

  useEffect(() => {
    if (!tracking) return;
    const scope = storageKey; const current = generation.current;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const controller = new AbortController();
    const active = () => !disposed && activeScope.current === scope && generation.current === current;
    async function poll() {
      const timeout = setTimeout(() => controller.abort(), 10000);
      try {
        const query = new URLSearchParams({ tenant_id: TENANT_ID, tool_id: toolId });
        const path = tracking!.taskId
          ? `/api/enterprise/external-business-tasks/${encodeURIComponent(tracking!.taskId)}?${query}`
          : `/api/enterprise/tools/${encodeURIComponent(toolId)}/test-requests/${encodeURIComponent(tracking!.clientRequestId)}?${query}`;
        const task = await api.get<Task>(path, { signal: controller.signal });
        if (!active()) return;
        if (!task.id || (tracking!.taskId && task.id !== tracking!.taskId)) throw new Error('任务状态与查询回执不一致');
        const next = { ...tracking!, taskId: task.id };
        if (!await enrichTracking(next, current) || !active()) return;
        setResult(task); setStatus(task.status); setQueryError('');
        if (!tracking!.taskId) setTracking(next);
        // Keep every request identity, including terminal/unknown states. Only a
        // separate explicit action after confirmed completion creates a new one.
        setBusy(task.status !== 'completed');
        if (stopped.has(task.status)) return;
      } catch (error) {
        if (!active()) return;
        setQueryError(error instanceof Error ? error.message : '任务状态查询失败');
        setBusy(true);
      } finally { clearTimeout(timeout); }
      if (active() && !controller.signal.aborted) timer = setTimeout(() => void poll(), 2000);
    }
    void poll();
    return () => { disposed = true; controller.abort(); clearTimeout(timer); };
  }, [tracking, toolId, storageKey, queryVersion]);

  async function retryStatus() { setQueryVersion((value) => value + 1); }

  async function submit(path: string, argumentsJson: Record<string, unknown>) {
    if (lock.current) { await retryStatus(); return; }
    lock.current = true;
    const current = generation.current; const scope = storageKey;
    const active = () => generation.current === current && activeScope.current === scope;
    setBusy(true); setStatus('submitting'); setQueryError('');
    let claim: Tracking | undefined;
    let created = false;
    try {
      if (!auth?.user.id) throw new Error('登录信息不可用，未发出调用。');
      if (!navigator.locks) throw new Error('浏览器不支持跨页面调用锁，未发出调用。请使用本地安全来源及支持的浏览器。');
      // Web Locks makes request-ID allocation atomic across tabs of this origin.
      await navigator.locks.request(storageKey, () => {
        const previous = localStorage.getItem(storageKey);
        if (previous) { claim = JSON.parse(previous) as Tracking; return; }
        const clientRequestId = globalThis.crypto?.randomUUID?.() || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
        claim = { clientRequestId }; persist(claim); created = true;
      });
    } catch (error) {
      if (active()) { setStatus('tracking_blocked'); setQueryError(`无法保存稳定调用记录，未发出新调用：${error instanceof Error ? error.message : ''}`); }
      return;
    }
    if (!active() || !claim) return;
    // Another tab may already own this claim. Query it rather than sending.
    if (claim.taskId) { setTracking(claim); return; }
    const key = claim.clientRequestId;
    // The tab which installed a new record is the only submitter. If a record
    // pre-existed without a task ID it may represent a lost response: query only.
    if (!created) { setTracking(claim); return; }
    const controller = new AbortController(); postController.current = controller;
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await api.postWithSignal<Receipt>(path, { tenant_id: TENANT_ID, arguments: argumentsJson, client_request_id: key }, controller.signal);
      if (!active()) return;
      if (response.success && response.data?.accepted && response.data.task_id) {
        const next = { clientRequestId: key, taskId: response.data.task_id };
        if (!await enrichTracking(next, current) || !active()) return;
        setTracking(next); setStatus('reconciling'); setResult(response);
      } else { if (!await enrichTracking(claim, current) || !active()) return; setTracking(claim); setStatus('outcome_unknown'); setQueryError('服务器未确认任务回执，请查询原调用；不会重复提交。'); }
    } catch {
      if (active() && await enrichTracking(claim, current) && active()) { setTracking(claim); setStatus('outcome_unknown'); setQueryError('提交结果待核实，正在查询原调用；不会重复提交。'); }
    } finally { clearTimeout(timeout); if (active()) setQueryVersion((value) => value + 1); }
  }

  async function startNew() {
    if (status !== 'completed' || !tracking || !navigator.locks) return;
    const scope = storageKey; const current = generation.current;
    let cleared = false;
    try {
      await navigator.locks.request(storageKey, () => {
        if (activeScope.current !== scope || generation.current !== current) return;
        const saved = JSON.parse(localStorage.getItem(storageKey) || 'null') as Tracking | null;
        if (saved?.clientRequestId !== tracking.clientRequestId) return;
        localStorage.removeItem(storageKey); cleared = true;
      });
    } catch { setQueryError('无法清除已完成记录，未开始新调用。'); return; }
    if (!cleared || activeScope.current !== scope || generation.current !== current) {
      setQueryError('另一页面已开始新的调用，请重新打开页面查询；未创建新调用。'); return;
    }
    generation.current += 1; lock.current = false;
    setTracking(null); setResult(null); setStatus(''); setBusy(false); setQueryError('');
  }
  return { result, status, busy, queryError, submit, retryStatus, startNew, taskId: tracking?.taskId || null };
}
