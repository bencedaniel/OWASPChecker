import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi10UnsafeConsumption } from '../../services/owaspChecks/Api10_uc.js';
import * as smartFetchModule from '../../services/smartFetch.js';

vi.mock('../../services/smartFetch.js', () => ({
    smartFetch: vi.fn()
}));

describe('OWASP API10:2023 - Unsafe Consumption', () => {
    let mockContext;

    beforeEach(() => {
        vi.clearAllMocks();
        mockContext = { targetUrl: 'http://test-api.local', harvestedIds: {}, allowDestructive: false };
    });

    it('Safe módban kihagyja a DELETE tesztet', async () => {
        const findings = await checkApi10UnsafeConsumption(
            { path: '/api/devices/{id}', method: 'DELETE', operation: {} },
            mockContext
        );
        expect(findings).toHaveLength(0);
        expect(smartFetchModule.smartFetch).not.toHaveBeenCalled();
    });

    it('Integrációs végpont tisztítatlan külső mintát ad vissza', async () => {
        smartFetchModule.smartFetch.mockResolvedValue({
            status: 200,
            text: async () => '<script>alert(1)</script>'
        });

        const findings = await checkApi10UnsafeConsumption(
            { path: '/api/webhooks/sync', method: 'POST', operation: {} },
            mockContext
        );

        expect(findings).toHaveLength(1);
        expect(findings[0].confidence).toBe('danger');
        expect(findings[0].owaspCategory).toBe('API10:2023');
    });

    it('Biztonságos válasz esetén nem ad találatot', async () => {
        smartFetchModule.smartFetch.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ status: 'ok', data: [] })
        });

        const findings = await checkApi10UnsafeConsumption(
            { path: '/api/users', method: 'GET', operation: {} },
            mockContext
        );

        expect(findings).toHaveLength(0);
    });
});
