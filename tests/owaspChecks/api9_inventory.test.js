import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi9ImproperInventory } from '../../services/owaspChecks/api9_old.js';
import * as smartFetchModule from '../../services/smartFetch.js';

vi.mock('../../services/smartFetch.js', () => ({
    smartFetch: vi.fn()
}));

describe('OWASP API9:2023 - Improper Inventory', () => {
    let mockContext;

    beforeEach(() => {
        vi.clearAllMocks();
        mockContext = { targetUrl: 'http://test-api.local', harvestedIds: {}, allowDestructive: false };
    });

    it('Deprecated végpont esetén alacsony találatot ad', async () => {
        const findings = await checkApi9ImproperInventory(
            { path: '/api/users', method: 'GET', operation: { deprecated: true } },
            mockContext
        );
        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('Low');
    });

    it('Aktív régi vagy tesztútvonalat talál', async () => {
        smartFetchModule.smartFetch.mockResolvedValue({ status: 200 });
        const findings = await checkApi9ImproperInventory(
            { path: '/api/v1/test-status', method: 'GET', operation: {} },
            mockContext
        );
        expect(smartFetchModule.smartFetch).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(1);
        expect(findings[0].owaspCategory).toBe('API9:2023');
    });

    it('Safe módban nem tesztel DELETE végpontot', async () => {
        const findings = await checkApi9ImproperInventory(
            { path: '/api/v1/old-resource', method: 'DELETE', operation: {} },
            mockContext
        );
        expect(findings).toHaveLength(0);
        expect(smartFetchModule.smartFetch).not.toHaveBeenCalled();
    });
});
