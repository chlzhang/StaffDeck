// @vitest-environment jsdom
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { useToolTest } from './useToolTest';

vi.mock('../api/client', () => ({ TENANT_ID: 'tenant', api: { postWithSignal: vi.fn(), get: vi.fn() } }));
const post = vi.mocked(api.postWithSignal);
const get = vi.mocked(api.get);
vi.mock('../auth', () => ({ getEnterpriseAuthSession: () => ({ user: { id: 'admin', tenant_id: 'tenant' } }) }));
const receipt = { success: true, data: { accepted: true, task_id: 'task-internal' } };

describe('saved tool task tracking', () => {
  beforeEach(() => { vi.useFakeTimers(); vi.resetAllMocks(); localStorage.clear(); Object.defineProperty(navigator, 'locks', { configurable: true, value: { request: async (_key: string, run: () => unknown) => run() } }); post.mockResolvedValue(receipt); });
  afterEach(() => { cleanup(); vi.useRealTimers(); });

  it('locks duplicate clicks and polls the same receipt until completion', async () => {
    get.mockResolvedValueOnce({ id: 'task-internal', status: 'working' })
      .mockResolvedValueOnce({ id: 'task-internal', status: 'completed', result: { answer: 42 } });
    const { result } = renderHook(() => useToolTest('tool'));
    await act(async () => {
      await Promise.all([result.current.submit('/test', {}), result.current.submit('/test', {})]);
    });
    expect(post).toHaveBeenCalledTimes(1);
    expect(result.current.busy).toBe(true);
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    expect(result.current.status).toBe('completed');
    expect(result.current.busy).toBe(false);
    expect(get).toHaveBeenCalledTimes(2);
    expect(get.mock.calls.every(([path]) => path.includes('/task-internal?'))).toBe(true);
  });

  it('retries a failed status GET without resubmission', async () => {
    get.mockRejectedValueOnce(new Error('unavailable'))
      .mockResolvedValue({ id: 'task-internal', status: 'failed' });
    const { result } = renderHook(() => useToolTest('tool'));
    await act(async () => { await result.current.submit('/test', {}); });
    expect(result.current.queryError).toBe('unavailable');
    expect(result.current.busy).toBe(true);
    await act(async () => { await result.current.submit('/test', {}); await vi.advanceTimersByTimeAsync(2000); });
    expect(post).toHaveBeenCalledTimes(1);
    expect(result.current.status).toBe('failed');
    expect(result.current.queryError).toBe('');
  });

  it('does not treat a bare untracked response as confirmed completion', async () => {
    post.mockResolvedValueOnce({ success: true, data: { answer: 42 } });
    const { result } = renderHook(() => useToolTest('tool'));
    await act(async () => { await result.current.submit('/test', {}); });
    expect(result.current.status).toBe('outcome_unknown');
    expect(result.current.busy).toBe(true);
    expect(get.mock.calls[0][0]).toContain('/test-requests/');
  });

  it('stops automatic GET on blocked tracking without enabling resubmission', async () => {
    get.mockResolvedValue({ id: 'task-internal', status: 'tracking_blocked', error: { code: 'PERMISSION_DENIED' } });
    const { result } = renderHook(() => useToolTest('tool'));
    await act(async () => { await result.current.submit('/test', {}); });
    expect(result.current.status).toBe('tracking_blocked');
    expect(result.current.busy).toBe(true);
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(get).toHaveBeenCalledTimes(1);
    await act(async () => { await result.current.submit('/test', {}); });
    expect(post).toHaveBeenCalledTimes(1);
    expect(get).toHaveBeenCalledTimes(2);
  });

  it('ignores the previous tool response after navigation', async () => {
    let resolve!: (value: unknown) => void;
    post.mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    const { result, rerender } = renderHook(({ id }) => useToolTest(id), { initialProps: { id: 'old' } });
    await act(async () => { void result.current.submit('/test', {}); await Promise.resolve(); });
    rerender({ id: 'new' });
    await act(async () => { resolve(receipt); });
    expect(result.current.result).toBeNull();
    expect(get).not.toHaveBeenCalled();
  });
});
