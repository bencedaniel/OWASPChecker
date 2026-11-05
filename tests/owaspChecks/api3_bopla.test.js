import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi3Bopla } from '../../services/owaspChecks/api3_bopla.js';

import * as smartFetchModule from '../../services/smartFetch.js';
vi.mock('../../services/smartFetch.js', () => ({
    smartFetch: vi.fn()
}));
describe('OWASP API3:2023 - BOPLA Modul Unit Tesztek', () => {
    
    let mockContext;

    beforeEach(() => {
        vi.clearAllMocks();
        
        mockContext = {
            targetUrl: 'http://test-api.local',
            harvestedIds: {
                users: ['user_789']
            }
        };
    });

    it('1. Át kell ugrania a végpontot, ha a metódus DELETE (nem GET, POST, PUT, PATCH)', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'DELETE',
            operation: {}
        };

        const findings = await checkApi3Bopla(endpoint, mockContext);
        
        expect(findings).toHaveLength(0);
        expect(smartFetchModule.smartFetch).not.toHaveBeenCalled();
    });

    // --- GET ÁG TESZTJEI (Excessive Data Exposure) ---

    it('2. GET - Üres tömbbel kell visszatérnie, ha a válasz nem tartalmaz érzékeny kulcsokat (Biztonságos)', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET', operation: {} };

        smartFetchModule.smartFetch.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ id: "user_789", name: "Bence", publicProfile: true })
        });

        const findings = await checkApi3Bopla(endpoint, mockContext);

        expect(smartFetchModule.smartFetch).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0);
    });

    it('3. GET - Üres tömbbel kell visszatérnie, ha a válasz nem JSON (pl. HTML 404 vagy 200 OK text)', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET', operation: {} };

        smartFetchModule.smartFetch.mockResolvedValue({
            status: 200,
            text: async () => "<html><body>Success but not JSON</body></html>"
        });

        const findings = await checkApi3Bopla(endpoint, mockContext);

        expect(smartFetchModule.smartFetch).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0); // Nem crashel a JSON.parse-nál!
    });

    it('4. GET - Sebezhetőség igazolása: A JSON válasz titkos mezőt (passwordHash) tartalmaz', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET', operation: {} };

        smartFetchModule.smartFetch.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ 
                id: "user_789", 
                name: "Bence", 
                passwordHash: "abc123secret" // Érzékeny adat!
            })
        });

        const findings = await checkApi3Bopla(endpoint, mockContext);

        expect(findings).toHaveLength(1);
        expect(findings[0].owaspCategory).toBe('API3:2023');
        expect(findings[0].description).toContain('Excessive Data Exposure');
        expect(findings[0].description).toContain('passwordHash');
    });

    it('5. GET - Sebezhetőség igazolása: Mélyen beágyazott rekurzív JSON kulcs (is_admin)', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'GET', operation: {} };

        smartFetchModule.smartFetch.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ 
                data: {
                    user: {
                        preferences: { theme: 'dark' },
                        flags: { is_admin: true } // Mélyen beágyazott érzékeny adat!
                    }
                }
            })
        });

        const findings = await checkApi3Bopla(endpoint, mockContext);

        expect(findings).toHaveLength(1);
        expect(findings[0].description).toContain('is_admin');
    });

    // --- NEM GET ÁG TESZTJEI (Mass Assignment) ---

    it('6. POST - Üres tömbbel kell visszatérnie, ha a szerver 403/400 hibával elutasítja a payloadot (Biztonságos)', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'POST', operation: {} };

        smartFetchModule.smartFetch.mockResolvedValue({ status: 403 }); // Elutasítva

        const findings = await checkApi3Bopla(endpoint, mockContext);

        expect(smartFetchModule.smartFetch).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0);
    });

    it('7. PUT - Sebezhetőség igazolása: A szerver elfogadta a mérgezett jogosultság-növelő payloadot (200 OK)', async () => {
        const endpoint = { path: '/api/users/{id}', method: 'PUT', operation: {} };

        smartFetchModule.smartFetch.mockResolvedValue({ status: 200 }); // Elfogadta

        const findings = await checkApi3Bopla(endpoint, mockContext);

        // Ellenőrizzük, hogy elment-e a kérés a becsempészett adatokkal
        expect(smartFetchModule.smartFetch).toHaveBeenCalledWith(
            'http://test-api.local/api/users/user_789',
            expect.objectContaining({
                method: 'PUT',
                body: expect.stringContaining('"isAdmin":true')
            }),
            mockContext,
            'tester'
        );

        expect(findings).toHaveLength(1);
        expect(findings[0].owaspCategory).toBe('API3:2023');
        expect(findings[0].severity).toBe('High');
        expect(findings[0].description).toContain('Mass Assignment');
        expect(findings[0].payloadUsed).toContain('isAdmin');
        expect(findings[0].payloadUsed).toContain('access_level');
    });

    it('8. PATCH - Dinamikus payload sémából generálása + mérgezés validálása', async () => {
        const endpoint = { 
            path: '/api/users/{id}', 
            method: 'PATCH', 
            operation: {
                requestBody: {
                    content: {
                        'application/json': {
                            schema: {
                                properties: {
                                    bio: { type: 'string' },
                                    age: { type: 'integer' }
                                }
                            }
                        }
                    }
                }
            } 
        };

        smartFetchModule.smartFetch.mockResolvedValue({ status: 204 }); // 204 No Content is siker

        const findings = await checkApi3Bopla(endpoint, mockContext);

        expect(smartFetchModule.smartFetch).toHaveBeenCalledWith(
            'http://test-api.local/api/users/user_789',
            expect.objectContaining({
                method: 'PATCH',
                body: expect.stringMatching(/bio.*age.*isAdmin.*role/) // Az eredeti séma és a merge-ölt mérgek is benne vannak
            }),
            mockContext,
            'tester'
        );

        expect(findings).toHaveLength(1);
    });
});