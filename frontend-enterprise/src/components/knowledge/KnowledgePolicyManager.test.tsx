// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { KnowledgePolicyManager } from './KnowledgePolicyManager';

const { get, post, put } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }));
vi.mock('../../api/client', () => ({ api: { get, post, put }, TENANT_ID: 't' }));
const provider = { id: 'p', name: 'Synthetic provider', endpoint: 'https://example.test/v1', model: 'mock', terms_reference: 'Synthetic terms', classifications: ['public'] };
const source = { ref: { envelope_id: 's', revision: 1 }, kind: 'document', title: 'Synthetic source', text: 'FULL_SOURCE', active: true, fresh: true, review_digest: 'exact-digest', created_at: '2026-10-25', send_allowed: false, reason: '待审批', policy: null };
const view = { ...source, ref: { envelope_id: 'v', revision: 1 }, kind: 'answer_view', title: '批准答复视图', text: 'DRAFT_VIEW_TEXT' };
let documentState = { document_id: 'doc', title: 'Synthetic source', text: 'FULL_SOURCE', updated_at: '', source, related_sources: [], views: [] as typeof view[] };
afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  documentState = { ...documentState, views: [] };
  get.mockImplementation(() => Promise.resolve(documentState));
  post.mockResolvedValue(view); put.mockResolvedValue(source);
});

it('saves a local draft without approving or answering', async () => {
  render(<KnowledgePolicyManager documentId="doc" provider={provider} onChanged={() => {}} />);
  await screen.findByText('FULL_SOURCE');
  fireEvent.change(screen.getByLabelText('新答复视图文本'), { target: { value: 'MANUAL_DRAFT' } });
  fireEvent.click(screen.getByRole('button', { name: '保存视图草稿' }));
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
  expect(post.mock.calls[0][0]).toBe('/api/enterprise/knowledge/governance/documents/doc/views');
  expect(post.mock.calls[0][1]).toMatchObject({ parent_ref: source.ref, text: 'MANUAL_DRAFT' });
  expect(put).not.toHaveBeenCalled();
  expect(post.mock.calls.some(([path]) => String(path).endsWith('/answer'))).toBe(false);
});

it('requires explicit policy confirmation and binds the current review digest', async () => {
  render(<KnowledgePolicyManager documentId="doc" provider={provider} onChanged={() => {}} />);
  await screen.findByText('FULL_SOURCE');
  const group = within(screen.getByRole('group', { name: '原资料政策' }));
  expect((group.getByRole('button', { name: '保存政策审批' }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(group.getByLabelText('资料分类'), { target: { value: 'public' } });
  fireEvent.change(group.getByLabelText('回答权限'), { target: { value: 'controlled_answer' } });
  fireEvent.change(group.getByLabelText('所选供应商许可'), { target: { value: 'allow' } });
  fireEvent.click(group.getByLabelText('我已核对具体资料、供应商和本次政策变更'));
  fireEvent.click(group.getByRole('button', { name: '保存政策审批' }));
  await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
  expect(put.mock.calls[0][1]).toMatchObject({ expected_digest: 'exact-digest', classification: 'public', answer_mode: 'controlled_answer', provider_decision: 'allow', confirm: true });
  expect(post).not.toHaveBeenCalled();
});

it('keeps stale views readable but forbids reapproval and replacement', async () => {
  documentState.views = [{ ...view, active: false, fresh: false }];
  render(<KnowledgePolicyManager documentId="doc" provider={provider} onChanged={() => {}} />);
  await screen.findByText('DRAFT_VIEW_TEXT');
  const card = within(screen.getByRole('group', { name: '答复视图 1' }));
  expect((card.getByRole('button', { name: '保存替换视图' }) as HTMLButtonElement).disabled).toBe(true);
  expect((card.getByRole('button', { name: '保存政策审批' }) as HTMLButtonElement).disabled).toBe(true);
  expect(put).not.toHaveBeenCalled(); expect(post).not.toHaveBeenCalled();
});

it('reviews an existing request template against its exact provider and digest', async () => {
  const { RequestPolicyReview } = await import('./KnowledgePolicyManager');
  const existing = { ...source, kind: 'system_template', policy: { classification: 'public', answer_mode: 'answer_with_quote', active: true, revision: 1, grants: { old: { purposes: ['answer'], representations: ['raw'] } }, denied_providers: [] } };
  get.mockResolvedValue(existing);
  render(<RequestPolicyReview sources={[{ envelope_id: 'template', kind: 'system_template', label: '固定回答模板政策', agent_id: 'employee' }]} provider={provider} onChanged={() => {}} />);
  const editor = within(await screen.findByRole('group', { name: '固定回答模板政策' }));
  expect(get.mock.calls[0][0]).toContain('/sources/template?tenant_id=t&provider_policy_id=p&agent_id=employee');
  expect((editor.getByRole('button', { name: '保存政策审批' }) as HTMLButtonElement).disabled).toBe(true);
  expect(editor.queryByRole('option', { name: '仅使用批准答复视图' })).toBeNull();
  fireEvent.change(editor.getByLabelText('所选供应商许可'), { target: { value: 'allow' } });
  fireEvent.click(editor.getByLabelText('我已核对具体资料、供应商和本次政策变更'));
  fireEvent.click(editor.getByRole('button', { name: '保存政策审批' }));
  await waitFor(() => expect(put).toHaveBeenCalledTimes(1));
  expect(put.mock.calls[0][1]).toMatchObject({ provider_policy_id: 'p', agent_id: 'employee', expected_digest: 'exact-digest', answer_mode: 'answer_with_quote', provider_decision: 'allow', confirm: true });
  expect(post).not.toHaveBeenCalled();
});
