import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi7Ssrf } from '../../services/owaspChecks/api7_ssrf.js';
import * as smartFetchModule from '../../services/smartFetch.js';

vi.mock('../../services/smartFetch.js', () => ({
    smartFetch: vi.fn()
}));

describe('OWASP API7:2023 - SSRF', () => {
    let mockContext;
    let endpoint;

    beforeEach(() => {
        vi.clearAllMocks();
        mockContext = { targetUrl: 'http://test-api.local', harvestedIds: {} };
        endpoint = {
            path: '/api/webhooks',
            method: 'POST',
            operation: {
                requestBody: {
                    content: {
                        'application/json': {
                            schema: { properties: { callbackUrl: { type: 'string', format: 'uri' } } }
                        }
                    }
                }
            }
        };
    });

    it('Átugorja azokat a végpontokat, amelyek nem tartalmaznak URL mezőt', async () => {
        const findings = await checkApi7Ssrf(
            { path: '/api/users', method: 'POST', operation: { requestBody: { content: { 'application/json': { schema: { properties: { name: { type: 'string' } } } } } } } },
            mockContext
        );
        expect(findings).toHaveLength(0);
        expect(smartFetchModule.smartFetch).not.toHaveBeenCalled();
    });

    it('Critical találatot ad, ha belső metaadat-szöveg szivárog', async () => {
        smartFetchModule.smartFetch.mockResolvedValue({
            status: 200,
            text: async () => 'ami-id meta-data'
        });

        const findings = await checkApi7Ssrf(endpoint, mockContext);

        expect(findings.length).toBeGreaterThan(0);
        expect(findings[0].confidence).toBe('danger');
        expect(findings[0].severity).toBe('Critical');
    });

    it('Nem ad találatot, ha a célcímeket minden esetben validációval elutasítják', async () => {
        smartFetchModule.smartFetch.mockResolvedValue({
            status: 422,
            text: async () => 'Validation error'
        });

        expect(await checkApi7Ssrf(endpoint, mockContext)).toHaveLength(0);
    });
});
