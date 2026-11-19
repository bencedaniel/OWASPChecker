import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi6BusinessFlows } from '../../services/owaspChecks/api6_business_flows.js';
import * as smartFetchModule from '../../services/smartFetch.js';

vi.mock('../../services/smartFetch.js', () => ({
    smartFetch: vi.fn()
}));

describe('OWASP API6:2023 - Sensitive Business Flows', () => {
    let mockContext;

    beforeEach(() => {
        vi.clearAllMocks();
        mockContext = {
            targetUrl: 'http://test-api.local',
            harvestedIds: {}
        };
    });

    it('Átugorja a nem érzékeny és nem író végpontokat', async () => {
        expect(await checkApi6BusinessFlows(
            { path: '/api/users', method: 'GET', operation: {} },
            mockContext
        )).toHaveLength(0);

        expect(await checkApi6BusinessFlows(
            { path: '/api/users', method: 'POST', operation: {} },
            mockContext
        )).toHaveLength(0);
        expect(smartFetchModule.smartFetch).not.toHaveBeenCalled();
    });

    it('Találatot ad, ha minden kupon- vagy regisztrációs próbálkozást elfogad', async () => {
        smartFetchModule.smartFetch.mockResolvedValue({ status: 201 });
        const endpoint = {
            path: '/api/register',
            method: 'POST',
            operation: { requestBody: { content: { 'application/json': { schema: { properties: { email: { type: 'string' } } } } } } }
        };

        const findings = await checkApi6BusinessFlows(endpoint, mockContext);

        expect(smartFetchModule.smartFetch).toHaveBeenCalledTimes(5);
        expect(findings).toHaveLength(1);
        expect(findings[0].owaspCategory).toBe('API6:2023');
        expect(findings[0].confidence).toBe('warning');
    });

    it('Nem generál találatot, ha a szerver elutasítja az ismételt műveleteket', async () => {
        smartFetchModule.smartFetch.mockResolvedValue({ status: 429 });
        const findings = await checkApi6BusinessFlows(
            { path: '/api/coupons/redeem', method: 'POST', operation: {} },
            mockContext
        );

        expect(smartFetchModule.smartFetch).toHaveBeenCalledTimes(5);
        expect(findings).toHaveLength(0);
    });
});
