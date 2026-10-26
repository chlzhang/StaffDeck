// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GovernedKnowledgeAnswer } from './GovernedKnowledgeAnswer';

const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../api/client', () => ({ api: { get, post }, TENANT_ID: 't' }));

const provider = { id: 'p', name: 'Synthetic provider', endpoint: 'https://example.test/v1', model: 'mock', classifications: ['public'], terms_reference: 'Synthetic reviewed terms' };
const pending = { id: 'r', owner_id: 'member', question: 'Synthetic question', review_digest: 'digest', question_ref: { envelope_id: 'q' },
  provider, sources: [{ title: 'Synthetic document', text: 'FULL_LOCAL_REVIEW_TEXT', classification: 'unclassified' }],
  status: 'blocked', code: 'DATA_UNCLASSIFIED', reason: '本次问题或资料尚未完成外发审批，请联系管理员审核。' };

afterEach(cleanup);

beforeEach(() => {
  vi.clearAllMocks();
  get.mockImplementation((path: string) => Promise.resolve(path.includes('answer-providers') ? [provider] : []));
});

describe('governed knowledge page entry', () => {
  it('does not restore a delayed answer after governance revocation succeeds', async () => {
    let revoked = false;
    let resolveAnswer: (value: { answer: string }) => void = () => {};
    const source = () => ({ ref: { envelope_id: 's', revision: 1 }, kind: 'document', title: 'Synthetic document', text: 'FULL_SOURCE', active: true, fresh: true, review_digest: revoked ? 'after' : 'before', created_at: '', send_allowed: !revoked, reason: '', policy: { classification: 'public', answer_mode: 'answer_with_quote', active: !revoked, revision: 1, grants: revoked ? {} : { p: { purposes: ['answer'], representations: ['raw'] } }, denied_providers: [] } });
    get.mockImplementation((path: string) => Promise.resolve(path.includes('answer-providers') ? [provider]
      : path.includes('/governance/') ? { document_id: 'doc', title: 'Synthetic document', text: 'FULL_SOURCE', updated_at: '', source: source(), related_sources: [], views: [] } : []));
    post.mockImplementation((path: string) => {
      if (path.endsWith('/answer')) return new Promise((resolve) => { resolveAnswer = resolve; });
      if (path.endsWith('/revoke')) { revoked = true; return Promise.resolve(source()); }
      return Promise.resolve({ ...pending, owner_id: 'admin', status: 'ready' });
    });
    render(<GovernedKnowledgeAnswer document={{ id: 'doc', title: 'Synthetic document' }} isAdmin currentUserId="admin" modelConfigs={[]} />);
    await screen.findByText('Synthetic provider');
    fireEvent.change(screen.getByLabelText('本次问题'), { target: { value: 'Synthetic question' } });
    fireEvent.click(screen.getByRole('button', { name: '准备问题（仅本地）' }));
    await screen.findByRole('button', { name: '生成回答' });
    fireEvent.click(screen.getByRole('button', { name: '生成回答' }));
    const policy = within(screen.getByRole('group', { name: '原资料政策' }));
    fireEvent.click(policy.getByLabelText('我已核对具体资料、供应商和本次政策变更'));
    fireEvent.click(policy.getByRole('button', { name: '撤销政策' }));
    await screen.findByText('政策已撤销，恢复须明确重新审批。');
    await act(async () => { resolveAnswer({ answer: 'MUST_NOT_REAPPEAR_AFTER_REVOKE' }); });
    expect(screen.queryByText('MUST_NOT_REAPPEAR_AFTER_REVOKE')).toBeNull();
  });
  it('lets a member select only returned approved views and prepares without sending', async () => {
    get.mockImplementation((path: string) => Promise.resolve(path.includes('answer-providers') ? [provider]
      : path.includes('approved-answer-views') ? [{ id: 'v-approved', text: 'APPROVED_VIEW_CHOICE', created_at: '2026-10-25' }] : []));
    post.mockResolvedValue({ ...pending, answer_mode: 'controlled_answer' });
    render(<GovernedKnowledgeAnswer document={{ id: 'doc', title: 'Synthetic document' }} isAdmin={false} currentUserId="member" modelConfigs={[]} />);
    await screen.findByText('Synthetic provider');
    fireEvent.change(screen.getByLabelText('回答方式'), { target: { value: 'controlled_answer' } });
    await screen.findByText('APPROVED_VIEW_CHOICE');
    fireEvent.change(screen.getByLabelText('选择批准答复视图'), { target: { value: 'v-approved' } });
    fireEvent.change(screen.getByLabelText('本次问题'), { target: { value: 'Synthetic question' } });
    fireEvent.click(screen.getByRole('button', { name: '准备问题（仅本地）' }));
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1));
    expect(post.mock.calls[0][1]).toMatchObject({ answer_mode: 'controlled_answer', view_ids: ['v-approved'] });
    expect(screen.queryByRole('heading', { name: '管理员：资料与答复视图' })).toBeNull();
    expect(post.mock.calls.some(([path]) => String(path).endsWith('/answer'))).toBe(false);
  });
  it('discards a pending preparation after switching documents', async () => {
    let resolvePrepare: (value: typeof pending) => void = () => {};
    post.mockReturnValue(new Promise((resolve) => { resolvePrepare = resolve; }));
    const view = render(<GovernedKnowledgeAnswer document={{ id: 'old', title: 'OLD_DOC' }} isAdmin={false} currentUserId="member" modelConfigs={[]} />);
    await screen.findByText('Synthetic provider');
    fireEvent.change(screen.getByLabelText('本次问题'), { target: { value: 'Synthetic question' } });
    fireEvent.click(screen.getByRole('button', { name: '准备问题（仅本地）' }));
    view.rerender(<GovernedKnowledgeAnswer document={{ id: 'new', title: 'NEW_DOC' }} isAdmin={false} currentUserId="member" modelConfigs={[]} />);
    resolvePrepare({ ...pending, status: 'ready' });
    await waitFor(() => expect(screen.getByText('NEW_DOC')).toBeTruthy());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.queryByText('FULL_LOCAL_REVIEW_TEXT')).toBeNull();
    expect(screen.queryByRole('button', { name: '生成回答' })).toBeNull();
  });
  it('prepares locally without approving or sending a member question', async () => {
    post.mockResolvedValue(pending);
    render(<GovernedKnowledgeAnswer document={{ id: 'doc', title: 'Synthetic document' }} isAdmin={false} currentUserId="member" modelConfigs={[]} />);
    await screen.findByText('Synthetic provider');
    fireEvent.change(screen.getByLabelText('本次问题'), { target: { value: 'Synthetic question' } });
    fireEvent.click(screen.getByRole('button', { name: '准备问题（仅本地）' }));
    await screen.findByText(pending.reason);
    expect(post).toHaveBeenCalledTimes(1);
    expect(post.mock.calls[0][0]).toBe('/api/enterprise/knowledge/answer-requests');
    expect(post.mock.calls[0][1]).not.toHaveProperty('classification');
    expect(screen.queryByRole('button', { name: '批准本次资料外发' })).toBeNull();
    expect((screen.getByRole('button', { name: '生成回答' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('requires explicit review then a separate requester send action', async () => {
    post.mockImplementation((path: string) => Promise.resolve(path.endsWith('/approve') ? { ...pending, status: 'ready', reason: '审批已保存，尚未发送问题。' } : path.endsWith('/answer') ? { answer: 'APPROVED_PRODUCT_OUTPUT' } : pending));
    render(<GovernedKnowledgeAnswer document={{ id: 'doc', title: 'Synthetic document' }} isAdmin currentUserId="member" modelConfigs={[]} />);
    await screen.findByText('Synthetic provider');
    fireEvent.change(screen.getByLabelText('本次问题'), { target: { value: 'Synthetic question' } });
    fireEvent.click(screen.getByRole('button', { name: '准备问题（仅本地）' }));
    await screen.findByText('FULL_LOCAL_REVIEW_TEXT');
    const approve = screen.getByRole('button', { name: '批准本次资料外发' }) as HTMLButtonElement;
    expect(approve.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('本次待审批资料分类'), { target: { value: 'public' } });
    fireEvent.click(screen.getByLabelText('我已核对完整资料并确认上述外发范围'));
    fireEvent.click(approve);
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2));
    expect(post.mock.calls[1][0]).toBe('/api/enterprise/knowledge/answer-requests/r/approve');
    expect(post.mock.calls.some(([path]) => String(path).endsWith('/answer'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: '生成回答' }));
    await screen.findByText('APPROVED_PRODUCT_OUTPUT');
    expect(post.mock.calls[2][0]).toBe('/api/enterprise/knowledge/answer-requests/r/answer');
  });

  it('shows an actionable denial and never renders a stale answer', async () => {
    get.mockImplementation((path: string) => Promise.resolve(path.includes('answer-providers') ? [provider] : path.includes('/answer-requests/r') ? { ...pending, status: 'ready' } : [{ ...pending, status: 'ready' }]));
    post.mockRejectedValue(new Error('资料外发许可已撤回，本次回答已停止。'));
    render(<GovernedKnowledgeAnswer isAdmin={false} currentUserId="member" modelConfigs={[]} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Synthetic question' }));
    get.mockResolvedValue({ ...pending, status: 'ready' });
    await waitFor(() => expect((screen.getByRole('button', { name: '生成回答' }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole('button', { name: '生成回答' }));
    await screen.findByText('资料外发许可已撤回，本次回答已停止。');
    expect(screen.queryByText('APPROVED_PRODUCT_OUTPUT')).toBeNull();
  });
});
