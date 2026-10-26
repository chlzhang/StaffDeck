import { afterEach, expect, it, vi } from 'vitest';
import { refreshEnterpriseAuth, logoutEnterpriseAuth } from './client';
afterEach(() => vi.unstubAllGlobals());
function stored(mode: string) {
  const session = { token: 'synthetic', refresh_mode: mode, user: { id: 'a', tenant_id: 't' } };
  const setItem = vi.fn();
  vi.stubGlobal('window', { localStorage: { getItem: () => JSON.stringify(session), setItem }, location: { reload: vi.fn() } });
  return setItem;
}
it('does not attempt cookie refresh for explicit local no-refresh sessions', async () => {
  stored('none'); const fetcher = vi.fn(async () => new Response('{}', { status: 401 })); vi.stubGlobal('fetch', fetcher);
  expect(await refreshEnterpriseAuth()).toBe(false);
  expect(fetcher).not.toHaveBeenCalled();
});
it('retains cookie refresh for provider-owned sessions', async () => {
  const setItem = stored('cookie');
  const fetcher = vi.fn(async () => new Response(JSON.stringify({ token: 'rotated', refresh_mode: 'cookie', user: { id: 'a', tenant_id: 't' } })));
  vi.stubGlobal('fetch', fetcher);
  expect(await refreshEnterpriseAuth()).toBe(true);
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(JSON.parse(setItem.mock.calls[0][1]).refresh_mode).toBe('cookie');
});

it('clears local identity only after the server confirms logout', async () => {
  const removeItem = vi.fn();
  vi.stubGlobal('window', { localStorage: { getItem: () => JSON.stringify({ token: 'synthetic', user: { id: 'a' } }), removeItem } });
  vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline'); }));
  await expect(logoutEnterpriseAuth()).rejects.toThrow('offline');
  expect(removeItem).not.toHaveBeenCalled();
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{"logged_out":true}')));
  await logoutEnterpriseAuth();
  expect(removeItem).toHaveBeenCalledTimes(1);
});
