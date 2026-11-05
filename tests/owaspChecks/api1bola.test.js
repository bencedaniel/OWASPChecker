import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkApi1Bola } from '../../services/owaspChecks/api1_bola.js'; 

// Importáljuk a modult a spy készítéséhez
import * as smartFetchModule from '../../services/smartFetch.js';

describe('OWASP API1:2023 - BOLA Modul Unit Tesztek', () => {
    
    let mockContext;
    let fetchSpy;

    beforeEach(() => {
        vi.clearAllMocks();
        
        // Helyesen spy-oljuk és mockoljuk a modult
        fetchSpy = vi.spyOn(smartFetchModule, 'smartFetch');
        
        mockContext = {
            targetUrl: 'http://test-api.local',
            testerUserId: 'user_tester_123',
            harvestedIds: {
                users: ['user_admin_1', 'user_tester_123'],
                devices: [] 
            }
        };
    });

    it('1. Át kell ugrania a végpontot, ha nincs benne path paraméter (Irreleváns)', async () => {
        const endpoint = {
            path: '/api/users', 
            method: 'GET',
            operation: {}
        };

        const findings = await checkApi1Bola(endpoint, mockContext);
        
        expect(findings).toHaveLength(0);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('2. Át kell ugrania a végpontot, ha a Recon nem talált ID-t a kategóriához', async () => {
        const endpoint = {
            path: '/api/devices/{id}',
            method: 'GET',
            operation: {}
        };

        const findings = await checkApi1Bola(endpoint, mockContext);
        
        expect(findings).toHaveLength(0);
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('3. Üres tömbbel kell visszatérnie, ha a szerver helyesen védekezik (403 Forbidden)', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'GET',
            operation: {}
        };

        fetchSpy.mockResolvedValue({
            status: 403,
            text: async () => JSON.stringify({ error: "Access Denied" })
        });

        const findings = await checkApi1Bola(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0);
    });

    it('4. Fals pozitív szűrés: Üres tömbbel kell visszatérnie, ha a szerver 200 OK-ba csomagol hibaüzenetet', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'GET',
            operation: {}
        };

        fetchSpy.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ status: false, error: "Unauthorized access" })
        });

        const findings = await checkApi1Bola(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0);
    });

    it('5. Sebezhetőség igazolása (GET): 200 OK válasz egy másik felhasználó adatára', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'GET',
            operation: {}
        };

        fetchSpy.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ name: "Admin User", balance: 9999 })
        });

        const findings = await checkApi1Bola(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledWith(
            'http://test-api.local/api/users/user_admin_1',
            expect.objectContaining({ method: 'GET' }),
            mockContext,
            'tester'
        );

        expect(findings).toHaveLength(1);
        expect(findings[0].owaspCategory).toBe('API1:2023');
        expect(findings[0].severity).toBe('High');
        expect(findings[0].confidence).toBe('danger');
    });

    it('6. Sebezhetőség igazolása (PUT): Dinamikus payload generálással és módosítással', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'PUT',
            operation: {
                requestBody: {
                    content: {
                        'application/json': {
                            schema: {
                                properties: {
                                    email: { type: 'string' },
                                    age: { type: 'integer' }
                                }
                            }
                        }
                    }
                }
            }
        };

        fetchSpy.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ success: true })
        });

        const findings = await checkApi1Bola(endpoint, mockContext);

        expect(fetchSpy).toHaveBeenCalledWith(
            'http://test-api.local/api/users/user_admin_1',
            expect.objectContaining({
                method: 'PUT',
                body: JSON.stringify({ email: "bola_test_string", age: 1 })
            }),
            mockContext,
            'tester'
        );

        expect(findings).toHaveLength(1);
        expect(findings[0].payloadUsed).toContain('bola_test_string');
    });

    it('7. Eredménytelen validáció (422 Unprocessable Entity) - Át kell ugrania', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'PUT',
            operation: {}
        };

        fetchSpy.mockResolvedValue({
            status: 422,
            text: async () => JSON.stringify({ message: "Validation error" })
        });

        const findings = await checkApi1Bola(endpoint, mockContext);
        expect(findings).toHaveLength(0);
    });

    it('8. Szerver összeomlás (500) idegen ID lekérésekor - Figyelmeztetést kell adnia', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'GET',
            operation: {}
        };

        fetchSpy.mockResolvedValue({
            status: 500,
            text: async () => "Internal Server Error"
        });

        const findings = await checkApi1Bola(endpoint, mockContext);

        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('Medium');
        expect(findings[0].confidence).toBe('warning');
        expect(findings[0].description).toContain('Szerver összeomlás');
    });
});