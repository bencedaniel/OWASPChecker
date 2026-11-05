import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi5Bfla } from '../../services/owaspChecks/api5_bfla.js';

import * as smartFetchModule from '../../services/smartFetch.js';

describe('OWASP API5:2023 - BFLA Modul Unit Tesztek', () => {
    
    let fetchSpy;
    let mockContext;

    beforeEach(() => {
        vi.clearAllMocks();
        fetchSpy = vi.spyOn(smartFetchModule, 'smartFetch');
        
        mockContext = {
            targetUrl: 'http://test-api.local',
            spec: { security: [{ bearerAuth: [] }] }, 
            harvestedIds: {}
        };
    });

    it('1. Át kell ugrania a végpontot, ha az nem admin jellegű (Irreleváns eset)', async () => {
        const endpoint = {
            path: '/api/public/users/1',
            method: 'GET',
            operation: {}
        };

        const findings = await checkApi5Bfla(endpoint, mockContext);
        
        expect(findings).toHaveLength(0); 
        expect(fetchSpy).not.toHaveBeenCalled(); 
    });

    it('2. Vissza kell adnia a sebezhetőséget, ha a szerver kiszolgálja az admint a mezei tokennel (Sebezhető eset)', async () => {
        const endpoint = {
            path: '/api/admin/delete-user',
            method: 'DELETE',
            operation: { security: [{ bearerAuth: [] }] }
        };

        fetchSpy.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ success: true })
        });

        const findings = await checkApi5Bfla(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(1); 
        expect(findings[0].owaspCategory).toBe('API5:2023');
        expect(findings[0].confidence).toBe('danger');
        expect(findings[0].severity).toBe('High');
    });

    it('3. Üres tömbbel kell visszatérnie, ha a szerver helyesen 403-at ad (Biztonságos eset)', async () => {
        const endpoint = {
            path: '/api/admin/delete-user',
            method: 'DELETE',
            operation: { security: [{ bearerAuth: [] }] }
        };

        fetchSpy.mockResolvedValue({
            status: 403,
            text: async () => JSON.stringify({ error: "Access Denied" })
        });

        const findings = await checkApi5Bfla(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0); 
    });
});