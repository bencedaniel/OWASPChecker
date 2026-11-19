import { describe, it, expect, vi } from 'vitest';
import { smartFetch } from '../services/smartFetch.js';

describe('smartFetch destructive request protection', () => {
    it('blocks DELETE in safe mode without calling fetch', async () => {
        const fetchSpy = vi.spyOn(globalThis, 'fetch');

        const response = await smartFetch(
            'http://test-api.local/api/devices/1',
            { method: 'DELETE' },
            { allowDestructive: false, spec: { paths: {} } }
        );

        expect(fetchSpy).not.toHaveBeenCalled();
        expect(response.status).toBe(405);
        expect(response.blockedBySafety).toBe(true);
        expect(response.headers.get('X-Scanner-Blocked')).toBe('delete');

        fetchSpy.mockRestore();
    });

    it('allows DELETE when destructive mode is explicitly enabled', async () => {
        const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
            new Response(null, { status: 204 })
        );

        const response = await smartFetch(
            'http://test-api.local/api/devices/1',
            { method: 'DELETE' },
            { allowDestructive: true, spec: { paths: {} } }
        );

        expect(fetchSpy).toHaveBeenCalledOnce();
        expect(response.status).toBe(204);

        fetchSpy.mockRestore();
    });
});
