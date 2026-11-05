import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkApi4RateLimit } from '../../services/owaspChecks/api4_rateLimiting.js'; 

import * as smartFetchModule from '../../services/smartFetch.js';

describe('OWASP API4:2023 - Rate Limiting Modul Unit Tesztek', () => {
    
    let mockContext;
    let fetchSpy;

    beforeEach(() => {
        vi.clearAllMocks();
        
        fetchSpy = vi.spyOn(smartFetchModule, 'smartFetch');
        vi.spyOn(global, 'setTimeout').mockImplementation((cb) => cb());
        
        mockContext = {
            targetUrl: 'http://test-api.local',
            harvestedIds: {
                users: ['user_999']
            }
        };
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    const createMockResponse = (status, headersObj = {}) => ({
        status,
        headers: {
            get: (key) => headersObj[key] || headersObj[key.toLowerCase()] || null
        }
    });

    it('1. Át kell ugrania a végpontot, ha az health vagy ping jellegű (Irreleváns)', async () => {
        const endpoint = { path: '/api/health/status', method: 'GET' };

        const findings = await checkApi4RateLimit(endpoint, mockContext);
        
        expect(findings).toHaveLength(0);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('2. Üres tömbbel kell visszatérnie, ha a szerver 429 Too Many Requests hibát dob (Biztonságos)', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET' };

        fetchSpy
            .mockResolvedValueOnce(createMockResponse(200))
            .mockResolvedValueOnce(createMockResponse(200))
            .mockResolvedValue(createMockResponse(429));

        const findings = await checkApi4RateLimit(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledTimes(3);
        expect(findings).toHaveLength(0);
    });

    it('3. Üres tömbbel kell visszatérnie, ha a szerver Rate Limit HTTP fejlécet küld (Biztonságos)', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET' };

        fetchSpy.mockResolvedValue(
            createMockResponse(200, { 'retry-after': '60' }) // Kisbetűvel biztos, ami biztos
        );

        const findings = await checkApi4RateLimit(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(findings).toHaveLength(0);
    });

    it('4. Sebezhetőség igazolása: Az összes (30) kérés 200 OK-val lemegy védelem nélkül', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET' };

        fetchSpy.mockResolvedValue(createMockResponse(200));

        const findings = await checkApi4RateLimit(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledTimes(30); 
        expect(findings).toHaveLength(1);
        expect(findings[0].owaspCategory).toBe('API4:2023');
        expect(findings[0].severity).toBe('Medium');
    });

    it('5. POST kérésnél dinamikusan üres JSON törzset kell küldenie, hogy ne body parse error-t kapjon', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'POST' };

        fetchSpy.mockResolvedValue(createMockResponse(429));

        await checkApi4RateLimit(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledWith(
            'http://test-api.local/api/users/user_999',
            expect.objectContaining({
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}) 
            }),
            mockContext,
            'tester'
        );
    });

    it('6. Nem ad sebezhetőséget, ha a ciklus végigmegy, de 4xx/5xx (nem 429) a státusz', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET' };

        fetchSpy.mockResolvedValue(createMockResponse(404));

        const findings = await checkApi4RateLimit(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledTimes(30);
        expect(findings).toHaveLength(0); 
    });
});