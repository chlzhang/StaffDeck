import { useEffect, useRef, useState } from 'react';
import { api, TENANT_ID } from '../../api/client';

export type GovernanceProvider = { id: string; name: string; endpoint: string; model: string; terms_reference: string; classifications: string[] };
type SourceState = {
  ref: { envelope_id: string; revision: number }; kind: string; title: string; text: string;
  active: boolean; fresh: boolean; review_digest: string; created_at: string;
  send_allowed: boolean; reason: string;
  policy: null | { classification: string; answer_mode: string; active: boolean; revision: number;
    grants: Record<string, { purposes: string[]; representations: string[] }>; denied_providers: string[] };
};
type DocumentState = { document_id: string; title: string; text: string; updated_at: string; source: SourceState | null; related_sources: SourceState[]; views: SourceState[] };
const root = '/api/enterprise/knowledge/governance';
const control = 'rounded border border-gray-300 px-3 py-2 text-sm disabled:opacity-50';

function PolicyEditor({ source, label, provider, agentId, onChanged }: {
  source: SourceState; label: string; provider?: GovernanceProvider; agentId?: string; onChanged: () => void;
}) {
  const [classification, setClassification] = useState(source.policy?.classification || 'unclassified');
  const [mode, setMode] = useState(source.kind === 'answer_view'
    ? source.policy?.answer_mode === 'none' ? 'none' : 'controlled_answer'
    : source.policy?.answer_mode || 'none');
  const [decision, setDecision] = useState(source.policy?.active && provider && source.policy.grants[provider.id]
    ? 'allow' : provider && source.policy?.denied_providers.includes(provider.id) ? 'deny' : 'pending');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const basis = () => ({ tenant_id: TENANT_ID, agent_id: agentId || undefined,
    provider_policy_id: provider?.id, expected_digest: source.review_digest, confirm: true });
  async function mutate(revoke: boolean) {
    if (!confirmed) return;
    setBusy(true); setError('');
    try {
      const path = `${root}/sources/${source.ref.envelope_id}`;
      if (revoke) await api.post(`${path}/revoke`, basis());
      else await api.put(`${path}/policy`, { ...basis(), classification, answer_mode: mode, provider_decision: decision });
      if (alive.current) { setConfirmed(false); onChanged(); }
    } catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : '政策操作失败，请刷新后重新核对'); }
    finally { if (alive.current) setBusy(false); }
  }
  return <fieldset aria-label={label} className="flex flex-col gap-3 rounded border p-3">
    <legend>{label}</legend>
    <p className="text-sm">{!source.active || !source.fresh ? '此版本已失效，不可重新批准使用。' : source.policy?.active === false ? '政策已撤销，恢复须明确重新审批。' : source.policy ? '已有政策，保存将更新本项许可。' : '尚无政策，默认禁止外发。'}</p>
    <p className="text-sm">{source.reason}</p>
    <label>资料分类<select aria-label="资料分类" className={`${control} ml-2`} value={classification} onChange={(e) => setClassification(e.target.value)}>
      <option value="unclassified">待分类</option><option value="public">公开</option><option value="internal">内部</option><option value="confidential">机密</option><option value="restricted">受限</option>
    </select></label>
    <label>回答权限<select aria-label="回答权限" className={`${control} ml-2`} value={mode} onChange={(e) => setMode(e.target.value)}>
      <option value="none">禁止模型使用</option>{['document', 'answer_view'].includes(source.kind) && <option value="controlled_answer">仅使用批准答复视图</option>}
      {source.kind !== 'answer_view' && <option value="answer_with_quote">允许原文回答与引用</option>}
    </select></label>
    <label>所选供应商许可<select aria-label="所选供应商许可" className={`${control} ml-2`} value={decision} onChange={(e) => setDecision(e.target.value)}>
      <option value="pending">待批准</option><option value="allow" disabled={!provider}>明确允许本次回答用途</option><option value="deny" disabled={!provider}>明确禁止此供应商</option>
    </select></label>
    <p className="text-sm">修改分类、回答方式或恢复已撤销政策会清空旧供应商许可，须逐一重审。保存和撤销都不会发送资料；撤销影响本项全部供应商。</p>
    <label><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />我已核对具体资料、供应商和本次政策变更</label>
    <div className="flex gap-2">
      <button type="button" className={control} disabled={busy || !confirmed || !source.active || !source.fresh} onClick={() => void mutate(false)}>保存政策审批</button>
      <button type="button" className={control} disabled={busy || !confirmed || !source.policy?.active} onClick={() => void mutate(true)}>撤销政策</button>
    </div>
    {error && <p role="alert" className="text-red-700">{error}</p>}
  </fieldset>;
}

export type RequestReviewSource = { envelope_id: string; kind: string; label: string; agent_id?: string | null };

function RequestSourceEditor({ descriptor, provider, onChanged }: {
  descriptor: RequestReviewSource; provider: GovernanceProvider; onChanged: () => void;
}) {
  const [source, setSource] = useState<SourceState | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    let cancelled = false;
    const query = new URLSearchParams({ tenant_id: TENANT_ID, provider_policy_id: provider.id });
    if (descriptor.agent_id) query.set('agent_id', descriptor.agent_id);
    void api.get<SourceState>(`${root}/sources/${descriptor.envelope_id}?${query}`)
      .then((value) => { if (!cancelled) setSource(value); })
      .catch((reason) => { if (!cancelled) setError(reason instanceof Error ? reason.message : '加载既有政策失败'); });
    return () => { cancelled = true; };
  }, [descriptor.envelope_id, descriptor.agent_id, provider.id]);
  return <div>{source && <><pre className="max-h-48 overflow-auto whitespace-pre-wrap text-sm">{source.text}</pre>
    <PolicyEditor key={`${source.ref.envelope_id}:${source.review_digest}:${provider.id}`} source={source} label={descriptor.label}
      provider={provider} agentId={descriptor.agent_id || undefined} onChanged={onChanged} /></>}
    {error && <p role="alert" className="text-red-700">{error}</p>}</div>;
}

export function RequestPolicyReview({ sources, provider, onChanged }: {
  sources: RequestReviewSource[]; provider: GovernanceProvider; onChanged: () => void;
}) {
  return <section aria-label="本请求既有政策重审" className="flex flex-col gap-3">
    <h4>本请求既有政策重审</h4>
    <p className="text-sm">仅管理员可逐项重新审核模板和问题。变更不自动发送，也不会复制其他供应商许可。</p>
    <p className="text-sm">{provider.name} · {provider.endpoint}</p>
    {sources.map((source) => <RequestSourceEditor key={`${source.envelope_id}:${provider.id}`} descriptor={source} provider={provider} onChanged={onChanged} />)}
  </section>;
}

function ViewCard({ source, index, provider, agentId, onChanged }: {
  source: SourceState; index: number; provider?: GovernanceProvider; agentId?: string; onChanged: () => void;
}) {
  const [replacement, setReplacement] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function replace() {
    if (!confirmed || !replacement.trim()) return;
    setBusy(true); setError('');
    try {
      await api.post(`${root}/sources/${source.ref.envelope_id}/replace-view`, {
        tenant_id: TENANT_ID, provider_policy_id: provider?.id, agent_id: agentId || undefined,
        expected_digest: source.review_digest, text: replacement, confirm: true,
      });
      if (alive.current) onChanged();
    } catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : '视图替换失败'); }
    finally { if (alive.current) setBusy(false); }
  }
  return <fieldset aria-label={`答复视图 ${index + 1}`} className="flex flex-col gap-3 rounded border p-3">
    <legend>答复视图 {index + 1}</legend>
    <p className="text-sm">{source.created_at} UTC · {source.active && source.fresh ? '资料版本有效' : '已失效，仅供本地核对'}</p>
    <pre className="max-h-64 overflow-auto whitespace-pre-wrap text-sm">{source.text}</pre>
    <PolicyEditor key={`${source.ref.envelope_id}:${source.review_digest}`} source={source} label="视图政策" provider={provider} agentId={agentId} onChanged={onChanged} />
    <label className="flex flex-col gap-2">替换视图文本<textarea aria-label="替换视图文本" className={control} maxLength={20000} value={replacement} onChange={(e) => setReplacement(e.target.value)} /></label>
    <label><input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />我确认旧视图立即失效，新视图须重新审批</label>
    <div><button type="button" className={control} disabled={busy || !source.active || !source.fresh || !confirmed || !replacement.trim()} onClick={() => void replace()}>保存替换视图</button></div>
    {error && <p role="alert" className="text-red-700">{error}</p>}
  </fieldset>;
}

export function KnowledgePolicyManager({ documentId, provider, agentId, onChanged }: {
  documentId: string; provider?: GovernanceProvider; agentId?: string; onChanged: () => void;
}) {
  const [data, setData] = useState<DocumentState | null>(null);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const alive = useRef(true);
  const sequence = useRef(0);
  useEffect(() => { alive.current = true; return () => { alive.current = false; sequence.current += 1; }; }, []);
  async function load() {
    const version = ++sequence.current;
    const query = new URLSearchParams({ tenant_id: TENANT_ID });
    if (provider) query.set('provider_policy_id', provider.id);
    if (agentId) query.set('agent_id', agentId);
    const value = await api.get<DocumentState>(`${root}/documents/${documentId}?${query}`);
    if (!alive.current || version !== sequence.current) return;
    if (!value || value.document_id !== documentId || !Array.isArray(value.views)) throw new Error('管理状态不可用，请刷新');
    setData(value);
  }
  useEffect(() => { void load().catch((reason) => { if (alive.current) setError(reason instanceof Error ? reason.message : '加载管理状态失败'); }); }, [documentId, provider?.id, agentId]);
  function changed() {
    if (!alive.current) return;
    onChanged();
    void load().catch((reason) => { if (alive.current) setError(reason instanceof Error ? reason.message : '加载管理状态失败'); });
  }
  async function saveDraft(register: boolean) {
    setBusy(true); setError('');
    try {
      if (register) {
        const query = new URLSearchParams({ tenant_id: TENANT_ID });
        if (agentId) query.set('agent_id', agentId);
        await api.post(`/api/enterprise/data-policies/documents/${documentId}/register?${query}`);
      } else {
        if (!data?.source || !draft.trim()) return;
        await api.post(`${root}/documents/${documentId}/views`, { tenant_id: TENANT_ID,
          provider_policy_id: provider?.id, agent_id: agentId || undefined, parent_ref: data.source.ref, text: draft });
      }
      if (alive.current) { setDraft(''); changed(); }
    } catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : '保存视图失败'); }
    finally { if (alive.current) setBusy(false); }
  }
  return <section aria-label="资料与答复视图管理" className="flex flex-col gap-4 rounded border p-4">
    <h3>管理员：资料与答复视图</h3>
    <div><button type="button" className={control} disabled={busy} onClick={() => { setError(''); void load().catch((reason) => { if (alive.current) setError(reason instanceof Error ? reason.message : '加载管理状态失败'); }); }}>刷新管理状态</button></div>
    <p className="text-sm">草稿只在本地保存，不会自动生成、审批或发送资料。所有父来源政策仍须同时满足。</p>
    {provider ? <><p className="text-sm">{provider.name} · {provider.model} · {provider.endpoint}</p><p className="text-sm">{provider.terms_reference}</p></> : <p className="text-sm">未选择供应商，本次不会新增供应商许可。</p>}
    {data && <>
      <details open><summary>完整原资料</summary><pre className="max-h-80 overflow-auto whitespace-pre-wrap text-sm">{data.text}</pre></details>
      {data.source ? <PolicyEditor key={`${data.source.ref.envelope_id}:${data.source.review_digest}`} source={data.source} label="原资料政策" provider={provider} agentId={agentId} onChanged={changed} />
        : <div><p>当前版本尚未登记；登记不会授予外发许可。</p><button type="button" className={control} disabled={busy} onClick={() => void saveDraft(true)}>登记当前资料版本</button></div>}
      {data.related_sources.map((source, index) => <PolicyEditor key={`${source.ref.envelope_id}:${source.review_digest}`} source={source} label={`同版本其他政策 ${index + 1}`} provider={provider} agentId={agentId} onChanged={changed} />)}
      <label className="flex flex-col gap-2">新答复视图文本<textarea aria-label="新答复视图文本" className={control} maxLength={20000} value={draft} onChange={(e) => setDraft(e.target.value)} /></label>
      <div><button type="button" className={control} disabled={busy || !data.source?.active || !data.source?.fresh || !draft.trim()} onClick={() => void saveDraft(false)}>保存视图草稿</button></div>
      {data.views.map((source, index) => <ViewCard key={`${source.ref.envelope_id}:${source.review_digest}`} source={source} index={index} provider={provider} agentId={agentId} onChanged={changed} />)}
    </>}
    {error && <p role="alert" className="text-red-700">{error}</p>}
  </section>;
}
