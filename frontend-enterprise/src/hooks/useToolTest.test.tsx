// @vitest-environment jsdom
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useToolTest } from './useToolTest';
const mocks = vi.hoisted(() => ({ post: vi.fn(), get: vi.fn() }));
vi.mock('../api/client', () => ({ TENANT_ID: 'tenant_demo', api: { postWithSignal: mocks.post, post: mocks.post, get: mocks.get } }));
vi.mock('../auth', () => ({ getEnterpriseAuthSession: () => ({ user: { id: 'admin', tenant_id: 'tenant_demo' } }) }));
beforeEach(() => {
  vi.useFakeTimers(); vi.resetAllMocks(); localStorage.clear();
  Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: async (_key: string, run: () => unknown) => run() } });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); });
const path = '/api/enterprise/tools/tool1/test';
const receipt = { success: true, data: { accepted: true, task_id: 'task1' } };
it('uses the current submit interface and stable request ID, then polls completion', async () => {
  mocks.post.mockResolvedValue(receipt); mocks.get.mockResolvedValueOnce({ id: 'task1', status: 'working' }).mockResolvedValue({ id: 'task1', status: 'completed', result: { answer: 'done' } });
  const { result } = renderHook(() => useToolTest('tool1'));
  await act(async () => { await result.current.submit(path, { value: 1 }); });
  expect(mocks.post.mock.calls[0][1].client_request_id).toMatch(/^[a-z0-9-]+$/);
  expect(result.current.busy).toBe(true);
  await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
  expect(result.current.status).toBe('completed'); expect(result.current.result).toMatchObject({ result: { answer: 'done' } });
  expect(mocks.post).toHaveBeenCalledTimes(1);
});
it('never turns a failed GET into another POST', async () => {
  mocks.post.mockResolvedValue(receipt); mocks.get.mockRejectedValueOnce(new Error('offline')).mockResolvedValue({ id: 'task1', status: 'completed' });
  const { result } = renderHook(() => useToolTest('tool1'));
  await act(async () => { await result.current.submit(path, {}); });
  expect(result.current.queryError).toContain('offline');
  await act(async () => { await result.current.submit(path, {}); await result.current.retryStatus(); });
  expect(mocks.post).toHaveBeenCalledTimes(1); expect(result.current.status).toBe('completed');
});
it('restores a pending task after reopening using only GET and aborts unmounted queries', async () => {
  mocks.post.mockResolvedValue(receipt); mocks.get.mockResolvedValue({ id: 'task1', status: 'working' });
  const first = renderHook(() => useToolTest('tool1'));
  await act(async () => { await first.result.current.submit(path, {}); }); first.unmount();
  const second = renderHook(() => useToolTest('tool1')); await act(async () => {});
  expect(second.result.current.busy).toBe(true); expect(second.result.current.taskId).toBe('task1');
  const signal = mocks.get.mock.calls.at(-1)?.[1].signal as AbortSignal; second.unmount(); expect(signal.aborted).toBe(true);
  expect(mocks.post).toHaveBeenCalledTimes(1);
});
it('queries the original stable request after ambiguous POST loss and never replays changed arguments', async () => {
  mocks.post.mockRejectedValue(new Error('timeout')); mocks.get.mockResolvedValue({ id: 'task1', status: 'outcome_unknown' });
  const first = renderHook(() => useToolTest('tool1'));
  await act(async () => { await first.result.current.submit(path, { value: 1 }); });
  const key = mocks.post.mock.calls[0][1].client_request_id;
  expect(mocks.get.mock.calls[0][0]).toContain('/test-requests/' + key);
  await act(async () => { await first.result.current.submit(path, { value: 2 }); });
  expect(mocks.post).toHaveBeenCalledTimes(1); expect(first.result.current.busy).toBe(true);
  first.unmount(); const reopened = renderHook(() => useToolTest('tool1')); await act(async () => {});
  expect(reopened.result.current.status).toBe('outcome_unknown'); expect(mocks.post).toHaveBeenCalledTimes(1);
});
it.each(['outcome_unknown', 'tracking_blocked', 'cancelled', 'expired'])('retains the claim for %s and only permits status queries', async (status) => {
  mocks.post.mockResolvedValue(receipt); mocks.get.mockResolvedValue({ id: 'task1', status });
  const { result } = renderHook(() => useToolTest('tool1')); await act(async () => { await result.current.submit(path, {}); });
  expect(result.current.busy).toBe(true);
  await act(async () => { await result.current.submit(path, {}); result.current.startNew(); });
  expect(mocks.post).toHaveBeenCalledTimes(1); expect(result.current.status).toBe(status);
});
it('blocks rapid double clicks before state updates', async () => {
  mocks.post.mockResolvedValue(receipt); mocks.get.mockResolvedValue({ id: 'task1', status: 'completed' });
  const { result } = renderHook(() => useToolTest('tool1'));
  await act(async () => { await Promise.all([result.current.submit(path, {}), result.current.submit(path, {})]); });
  expect(mocks.post).toHaveBeenCalledTimes(1);
});
it('retains completed receipt until a separate explicit new-call action', async () => {
  mocks.post.mockResolvedValue(receipt); mocks.get.mockResolvedValue({ id: 'task1', status: 'completed' });
  const { result } = renderHook(() => useToolTest('tool1')); await act(async () => { await result.current.submit(path, {}); });
  const firstKey = mocks.post.mock.calls[0][1].client_request_id;
  await act(async () => { await result.current.submit(path, {}); }); expect(mocks.post).toHaveBeenCalledTimes(1);
  await act(async () => { await result.current.startNew(); }); await act(async () => { await result.current.submit(path, {}); });
  expect(mocks.post).toHaveBeenCalledTimes(2); expect(mocks.post.mock.calls[1][1].client_request_id).not.toBe(firstKey);
});
it('fails closed when durable browser storage cannot retain the claim', async () => {
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('quota'); });
  const { result } = renderHook(() => useToolTest('tool1')); await act(async () => { await result.current.submit(path, {}); });
  expect(mocks.post).not.toHaveBeenCalled(); expect(result.current.queryError).toContain('保存');
});
it('queries a pending claim created by another browser context without POST', async () => {
  mocks.get.mockResolvedValue({ id: 'other-task', status: 'outcome_unknown' });
  const { result } = renderHook(() => useToolTest('tool1'));
  localStorage.setItem(JSON.stringify(['staffdeck-tool-test-v2', 'tenant_demo', 'admin', '', 'tool1']), JSON.stringify({ clientRequestId: 'other-window-request' }));
  await act(async () => { await result.current.submit(path, {}); });
  expect(mocks.post).not.toHaveBeenCalled(); expect(result.current.status).toBe('outcome_unknown');
});
it('does not erase another window pending claim from a stale completed view', async () => {
  mocks.post.mockResolvedValue(receipt); mocks.get.mockResolvedValue({ id: 'task1', status: 'completed' });
  const { result } = renderHook(() => useToolTest('tool1')); await act(async () => { await result.current.submit(path, {}); });
  const storageKey = JSON.stringify(['staffdeck-tool-test-v2', 'tenant_demo', 'admin', '', 'tool1']);
  localStorage.setItem(storageKey, JSON.stringify({ clientRequestId: 'new-other-window-pending' }));
  await act(async () => { await result.current.startNew(); });
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual({ clientRequestId: 'new-other-window-pending' });
  expect(mocks.post).toHaveBeenCalledTimes(1);
});
it('does not overwrite a newer unknown claim with an old delayed POST receipt', async () => {
  let resolve!: (value: unknown) => void;
  mocks.post.mockImplementation(() => new Promise((done) => { resolve = done; }));
  mocks.get.mockResolvedValue({ id: 'new-task', status: 'outcome_unknown' });
  const { result } = renderHook(() => useToolTest('tool1'));
  let pending!: Promise<void>;
  await act(async () => { pending = result.current.submit(path, {}); await Promise.resolve(); });
  const storageKey = JSON.stringify(['staffdeck-tool-test-v2', 'tenant_demo', 'admin', '', 'tool1']);
  localStorage.setItem(storageKey, JSON.stringify({ clientRequestId: 'new-pending', taskId: 'new-task' }));
  await act(async () => { resolve(receipt); await pending; });
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual({ clientRequestId: 'new-pending', taskId: 'new-task' });
  expect(result.current.status).toBe('outcome_unknown'); expect(mocks.post).toHaveBeenCalledTimes(1);
});
it('does not overwrite a newer unknown claim with an old delayed request lookup', async () => {
  let resolve!: (value: unknown) => void;
  mocks.get.mockImplementationOnce(() => new Promise((done) => { resolve = done; })).mockResolvedValue({ id: 'new-task', status: 'outcome_unknown' });
  const storageKey = JSON.stringify(['staffdeck-tool-test-v2', 'tenant_demo', 'admin', '', 'tool1']);
  localStorage.setItem(storageKey, JSON.stringify({ clientRequestId: 'old-pending' }));
  const { result } = renderHook(() => useToolTest('tool1')); await act(async () => {});
  localStorage.setItem(storageKey, JSON.stringify({ clientRequestId: 'new-pending', taskId: 'new-task' }));
  await act(async () => { resolve({ id: 'old-task', status: 'completed' }); });
  expect(JSON.parse(localStorage.getItem(storageKey)!)).toEqual({ clientRequestId: 'new-pending', taskId: 'new-task' });
  expect(result.current.status).toBe('outcome_unknown'); expect(mocks.post).not.toHaveBeenCalled();
});
it('retains a stable identifier when randomUUID is unavailable', async () => {
  vi.stubGlobal('crypto', {});
  try {
    mocks.post.mockResolvedValue(receipt); mocks.get.mockResolvedValue({ id: 'task1', status: 'completed' });
    const { result } = renderHook(() => useToolTest('tool1'));
    await act(async () => { await result.current.submit(path, {}); await result.current.submit(path, {}); });
    expect(mocks.post).toHaveBeenCalledTimes(1);
    expect(mocks.post.mock.calls[0][1].client_request_id).toMatch(/^[a-z0-9-]{1,128}$/);
  } finally { vi.unstubAllGlobals(); }
});
