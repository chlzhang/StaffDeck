import { useEffect, useRef, useState } from 'react';
import { api, TENANT_ID } from '../../api/client';
import type { ModelConfigRead } from '../../types';
import { KnowledgePolicyManager, RequestPolicyReview, type RequestReviewSource } from './KnowledgePolicyManager';

type Provider = { id: string; name: string; endpoint: string; model: string; classifications: string[]; terms_reference: string };
type AnswerPreparation = {
  id: string; owner_id: string; question: string; review_digest: string;
  provider: Provider; sources: { title: string; text: string; classification: string }[];
  status: 'ready' | 'blocked'; code?: string; reason: string;
  answer_mode?: 'answer_with_quote' | 'controlled_answer';
  admin_review_sources?: RequestReviewSource[];
};
type Props = {
  document?: { id: string; title?: string | null } | null;
  agentId?: string; isAdmin: boolean; currentUserId: string; modelConfigs: ModelConfigRead[];
};
const root = '/api/enterprise/knowledge';
const control = 'rounded border border-gray-300 px-3 py-2 text-sm disabled:opacity-50';
const classificationName = (value: string) => ({ public: '公开', internal: '内部', confidential: '机密', restricted: '受限', unclassified: '待分类' }[value] || value);

export function GovernedKnowledgeAnswer({ document, agentId, isAdmin, currentUserId, modelConfigs }: Props) {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [requests, setRequests] = useState<AnswerPreparation[]>([]);
  const [providerId, setProviderId] = useState('');
  const [question, setQuestion] = useState('');
  const [active, setActive] = useState<AnswerPreparation | null>(null);
  const [classification, setClassification] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [answer, setAnswer] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [setupModel, setSetupModel] = useState('');
  const [terms, setTerms] = useState('');
  const [includeInternal, setIncludeInternal] = useState(false);
  const [termsConfirmed, setTermsConfirmed] = useState(false);
  const [answerMode, setAnswerMode] = useState('answer_with_quote');
  const [views, setViews] = useState<{ id: string; text: string; created_at: string }[]>([]);
  const [viewId, setViewId] = useState('');
  const [governanceVersion, setGovernanceVersion] = useState(0);
  const sequence = useRef(0);
  const contextKey = JSON.stringify([currentUserId, agentId, document?.id, isAdmin, providerId, answerMode, viewId]);
  const context = useRef(contextKey);
  const contextEpoch = useRef(0);
  if (context.current !== contextKey) { context.current = contextKey; contextEpoch.current += 1; }
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  async function refresh() {
    const version = ++sequence.current;
    const scope = context.current;
    const epoch = contextEpoch.current;
    const [providerRows, requestRows] = await Promise.all([
      api.get<Provider[]>(`${root}/answer-providers?tenant_id=${encodeURIComponent(TENANT_ID)}`),
      api.get<AnswerPreparation[]>(`${root}/answer-requests?tenant_id=${encodeURIComponent(TENANT_ID)}`),
    ]);
    if (!mounted.current || scope !== context.current || epoch !== contextEpoch.current || version !== sequence.current) return;
    setProviders(providerRows);
    setRequests(requestRows);
    setProviderId((previous) => providerRows.some((row) => row.id === previous) ? previous : providerRows[0]?.id || '');
  }
  useEffect(() => {
    setActive(null); setAnswer(''); setError(''); setProviders([]); setRequests([]);
    void refresh().catch((reason) => setError(reason instanceof Error ? reason.message : '获取审批状态失败'));
    return () => { sequence.current += 1; };
  }, [currentUserId, agentId]);
  useEffect(() => { setActive(null); setAnswer(''); setBusy(false); }, [contextKey]);
  useEffect(() => { setConfirmed(false); setClassification(''); }, [active?.id]);
  useEffect(() => {
    let cancelled = false;
    setViews([]);
    if (answerMode !== 'controlled_answer' || !document || !providerId) { setViewId(''); return; }
    const query = new URLSearchParams({ tenant_id: TENANT_ID, provider_policy_id: providerId });
    if (agentId) query.set('agent_id', agentId);
    void api.get<typeof views>(`${root}/documents/${document.id}/approved-answer-views?${query}`)
      .then((rows) => { if (!cancelled) { setViews(rows); setViewId((previous) => rows.some((row) => row.id === previous) ? previous : ''); } })
      .catch((reason) => { if (!cancelled) { setViewId(''); setError(reason instanceof Error ? reason.message : '读取批准视图失败'); } });
    return () => { cancelled = true; };
  }, [answerMode, document?.id, providerId, agentId, governanceVersion]);

  async function action(run: (current: () => boolean) => Promise<void>) {
    const scope = context.current;
    const epoch = contextEpoch.current;
    const current = () => mounted.current && scope === context.current && epoch === contextEpoch.current;
    setBusy(true); setError(''); setAnswer('');
    try { await run(current); } catch (reason) { if (current()) { setActive(null); setError(reason instanceof Error ? reason.message : '操作失败，请检查资料许可'); } }
    finally { if (current()) setBusy(false); }
  }
  function prepare() {
    if (!document) return;
    void action(async (current) => {
      const result = await api.post<AnswerPreparation>(`${root}/answer-requests`, {
        tenant_id: TENANT_ID, agent_id: agentId || undefined, provider_policy_id: providerId,
        question, document_ids: [document.id],
        answer_mode: answerMode, view_ids: answerMode === 'controlled_answer' ? [viewId] : [],
      });
      if (!current()) return;
      setActive(result); await refresh();
    });
  }
  function openRequest(id: string) {
    void action(async (current) => {
      const result = await api.get<AnswerPreparation>(`${root}/answer-requests/${id}?tenant_id=${encodeURIComponent(TENANT_ID)}`);
      if (current()) setActive(result);
    });
  }
  function approve() {
    if (!active || !confirmed || !classification) return;
    void action(async (current) => {
      const result = await api.post<AnswerPreparation>(`${root}/answer-requests/${active.id}/approve`, {
        tenant_id: TENANT_ID, review_digest: active.review_digest, classification, confirm: true,
      });
      if (!current()) return;
      setActive(result); setConfirmed(false); await refresh();
    });
  }
  function send() {
    if (!active || active.status !== 'ready' || active.owner_id !== currentUserId) return;
    void action(async (current) => {
      const result = await api.post<{ answer: string }>(`${root}/answer-requests/${active.id}/answer`, { tenant_id: TENANT_ID });
      if (current()) setAnswer(result.answer);
    });
  }
  function approveProvider() {
    if (!termsConfirmed || !setupModel || !terms.trim()) return;
    void action(async (current) => {
      await api.post('/api/enterprise/data-policies/providers', {
        tenant_id: TENANT_ID, model_config_id: setupModel, purposes: ['answer'],
        classifications: includeInternal ? ['public', 'internal'] : ['public'], terms_reference: terms,
      });
      if (!current()) return;
      setTermsConfirmed(false); await refresh();
    });
  }
  function governanceChanged() {
    contextEpoch.current += 1;
    setBusy(false);
    setActive(null); setAnswer(''); setGovernanceVersion((value) => value + 1);
    void refresh().catch((reason) => { if (mounted.current) setError(reason instanceof Error ? reason.message : '获取审批状态失败'); });
  }
  function refreshStatus() {
    void action(async (current) => {
      await refresh();
      if (active) {
        const updated = await api.get<AnswerPreparation>(`${root}/answer-requests/${active.id}?tenant_id=${encodeURIComponent(TENANT_ID)}`);
        if (current()) setActive(updated);
      }
      if (current()) setGovernanceVersion((value) => value + 1);
    });
  }

  return <section className="flex flex-col gap-4" aria-label="受控知识问答">
    <p className="text-sm text-gray-600">问题与资料先在本地准备，经管理员审核后，由提问者另行点击生成回答。准备和审批都不会发送资料。</p>
    <p className="text-sm text-gray-600">普通聊天、数字员工工具与后台模型调用尚未接入此审批流程，保持停用；本地入库和检索可继续使用。</p>
    <label>回答供应商<select aria-label="回答供应商" className={`${control} ml-2`} value={providerId} onChange={(event) => setProviderId(event.target.value)}>
      {!providers.length && <option value="">暂无已批准供应商</option>}
      {providers.map((provider) => <option key={provider.id} value={provider.id}>{provider.name}</option>)}
    </select></label>
    <label>回答方式<select aria-label="回答方式" className={`${control} ml-2`} value={answerMode} onChange={(e) => setAnswerMode(e.target.value)}>
      <option value="answer_with_quote">允许原文的受控问答</option><option value="controlled_answer">仅批准答复视图</option>
    </select></label>
    {answerMode === 'controlled_answer' && <>
      <label>选择批准答复视图<select aria-label="选择批准答复视图" className={`${control} ml-2`} value={viewId} onChange={(e) => setViewId(e.target.value)}>
        <option value="">请选择已批准视图</option>
        {views.map((view) => <option value={view.id} key={view.id}>{view.text.slice(0, 80)}</option>)}
      </select></label>
      {!views.length && <p>暂无适用于所选供应商的批准视图，请管理员审核。</p>}
    </>}
    <p className="text-sm">{document?.title || '先从上方选择一篇已入库资料，再准备问题。'}</p>
    <label className="flex flex-col gap-2">本次问题<textarea aria-label="本次问题" className={control} maxLength={20000} value={question} onChange={(event) => setQuestion(event.target.value)} /></label>
    <div><button type="button" className={control} disabled={busy || !document || !providerId || !question.trim() || (answerMode === 'controlled_answer' && !views.some((value) => value.id === viewId))} onClick={prepare}>准备问题（仅本地）</button></div>
    <div className="flex flex-wrap gap-2" aria-label="待审核与历史问题">
      <button type="button" className={control} disabled={busy} onClick={refreshStatus}>刷新审批状态</button>
      {requests.map((request) => <button type="button" className={control} key={request.id} disabled={busy} onClick={() => openRequest(request.id)}>{request.question}</button>)}
    </div>
    {active && <div className="flex flex-col gap-3 rounded border p-4">
      <p>{active.question}</p><p role="status">{active.reason}</p>
      <p className="text-sm">{active.answer_mode === 'controlled_answer' ? '本请求仅使用批准视图，模型自由文本不会显示。' : '本请求按允许原文的政策审核。'}</p>
      <p className="text-sm">{active.provider.name} · {active.provider.model} · {active.provider.endpoint}</p>
      <p className="text-sm">{active.provider.terms_reference}</p>
      {active.sources.map((source, index) => <details key={index}>
        <summary>{source.title} · {classificationName(source.classification)}</summary>
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap text-sm">{source.text}</pre>
      </details>)}
      {isAdmin && <fieldset className="flex flex-col gap-3 border-t pt-3">
        <legend>管理员审核</legend>
        <p className="text-sm">审核只批准尚未分类的本次问题和资料；已有受限政策不会被覆盖。禁止原文外发的资料须使用批准视图。</p>
        <label>本次待审批资料分类<select aria-label="本次待审批资料分类" className={`${control} ml-2`} value={classification} onChange={(event) => setClassification(event.target.value)}>
          <option value="">请明确选择分类</option>
          {active.provider.classifications.includes('public') && <option value="public">公开</option>}
          {active.provider.classifications.includes('internal') && <option value="internal">内部</option>}
        </select></label>
        <label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />我已核对完整资料并确认上述外发范围</label>
        <div><button type="button" className={control} disabled={busy || !confirmed || !classification || !active.sources.length} onClick={approve}>批准本次资料外发</button></div>
      </fieldset>}
      {isAdmin && active.admin_review_sources && <RequestPolicyReview key={active.id} sources={active.admin_review_sources} provider={active.provider} onChanged={governanceChanged} />}
      <div><button type="button" className={control} disabled={busy || active.status !== 'ready' || active.owner_id !== currentUserId} onClick={send}>生成回答</button></div>
      {active.owner_id !== currentUserId && <p className="text-sm">审核完成后，须由原提问者发送问题。</p>}
    </div>}
    {isAdmin && <details><summary>管理员：批准模型供应商</summary><div className="mt-3 flex flex-col gap-3">
      <p className="text-sm">请先核实供应商条款、保留策略与允许的数据分类；此操作只登记许可，不发送资料。</p>
      <label>模型配置<select aria-label="模型配置" className={`${control} ml-2`} value={setupModel} onChange={(event) => setSetupModel(event.target.value)}>
        <option value="">请选择模型</option>{modelConfigs.map((model) => <option key={model.id} value={model.id}>{model.name}</option>)}
      </select></label>
      <label className="flex flex-col gap-2">条款审核依据<input className={control} value={terms} maxLength={500} onChange={(event) => setTerms(event.target.value)} /></label>
      <label><input type="checkbox" checked={includeInternal} onChange={(event) => setIncludeInternal(event.target.checked)} />条款明确允许发送内部资料</label>
      <label><input type="checkbox" checked={termsConfirmed} onChange={(event) => setTermsConfirmed(event.target.checked)} />我已确认供应商及上述用途许可</label>
      <div><button type="button" className={control} disabled={busy || !termsConfirmed || !setupModel || !terms.trim()} onClick={approveProvider}>登记供应商许可</button></div>
    </div></details>}
    {isAdmin && document && <KnowledgePolicyManager
      key={`${document.id}:${providerId}:${agentId || ''}`}
      documentId={document.id} provider={providers.find((value) => value.id === providerId)} agentId={agentId}
      onChanged={governanceChanged} />}
    {error && <p role="alert" className="text-red-700">{error}</p>}
    {answer && <div aria-label="受控回答" className="whitespace-pre-wrap rounded border p-4">{answer}</div>}
  </section>;
}
