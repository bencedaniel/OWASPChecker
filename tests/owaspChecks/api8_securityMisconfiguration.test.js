import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi8SecurityMisconfiguration } from '../../services/owaspChecks/api8_SM.js';
import * as smartFetchModule from '../../services/smartFetch.js';

vi.mock('../../services/smartFetch.js', () => ({
    smartFetch: vi.fn()
}));

describe('OWASP API8:2023 - Security Misconfiguration', () => {
    let mockContext;

    beforeEach(() => {
        vi.clearAllMocks();
        mockContext = { targetUrl: 'http://test-api.local', harvestedIds: {}, allowDestructive: false };
    });

    it('Safe módban kihagyja a DELETE végpontot', async () => {
        const findings = await checkApi8SecurityMisconfiguration(
            { path: '/api/devices/{id}', method: 'DELETE', operation: {} },
            mockContext
        );
        expect(findings).toHaveLength(0);
        expect(smartFetchModule.smartFetch).not.toHaveBeenCalled();
    });

    it('Veszélyes CORS és hiányzó biztonsági fejlécek esetén találatot ad', async () => {
        smartFetchModule.smartFetch
            .mockResolvedValueOnce({
                status: 200,
                headers: new Headers({
                    'access-control-allow-origin': '*',
                    'access-control-allow-credentials': 'true'
                }),
                text: async () => 'success'
            })
            .mockResolvedValueOnce({
                status: 400,
                headers: new Headers(),
                text: async () => 'bad request'
            });

        const findings = await checkApi8SecurityMisconfiguration(
            { path: '/api/users', method: 'GET', operation: {} },
            mockContext
        );

        expect(findings.some(f => f.description.includes('CORS'))).toBe(true);
        expect(findings.some(f => f.description.includes('biztonsági HTTP fejecek'))).toBe(true);
    });

    it('Stack trace kiszivárgáskor közepes találatot ad', async () => {
        smartFetchModule.smartFetch
            .mockResolvedValueOnce({
                status: 200,
                headers: new Headers(),
                text: async () => 'success'
            })
            .mockResolvedValueOnce({
                status: 500,
                headers: new Headers(),
                text: async () => 'Traceback (most recent call last): at module.'
            });

        const findings = await checkApi8SecurityMisconfiguration(
            { path: '/api/status', method: 'GET', operation: {} },
            mockContext
        );

        expect(findings.some(f => f.description.includes('Stack Trace Disclosure'))).toBe(true);
    });
});
