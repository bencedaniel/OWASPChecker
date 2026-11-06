import { describe, it, expect, vi, beforeEach } from 'vitest';
import { brokenAuthCheck } from '../../services/owaspChecks/api2_brokenAuth.js';
// 1. Mockoljuk a globális natív fetch-et
global.fetch = vi.fn();

describe('OWASP API2:2023 - Broken Authentication Modul Unit Tesztek', () => {
    
    let mockContext;

    beforeEach(() => {
        vi.clearAllMocks();
        
        mockContext = {
            targetUrl: 'http://test-api.local',
            spec: {
                // Globálisan hitelesítést váró API specifikáció szimulálása
                security: [{ bearerAuth: [] }]
            },
            harvestedIds: {
                users: ['user_123']
            }
        };
    });

    it('1. Át kell ugrania a végpontot, ha az nem vár el hitelesítést (Irreleváns)', async () => {
        const endpoint = {
            path: '/api/public/status',
            method: 'GET',
            operation: {
                // A specifikus végpont felülbírálja a globális security-t egy üres tömbbel (publikus)
                security: [] 
            }
        };

        const findings = await brokenAuthCheck(endpoint, mockContext);
        
        expect(findings).toHaveLength(0);
        expect(global.fetch).not.toHaveBeenCalled();
    });

    it('2. Üres tömbbel kell visszatérnie, ha a szerver helyesen védekezik (401 Unauthorized)', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'GET',
            operation: {} // Globális security érvényesül
        };

        // SZIMULÁLÁS: A biztonságos szerver elutasítja a token nélküli kérést
        global.fetch.mockResolvedValue({
            status: 401,
            text: async () => JSON.stringify({ error: "Unauthorized" })
        });

        const findings = await brokenAuthCheck(endpoint, mockContext);

        expect(global.fetch).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0);
    });

    it('3. Fals pozitív szűrés: Üres tömbbel kell visszatérnie, ha a szerver 200 OK-ba csomagol hibaüzenetet', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'GET',
            operation: {}
        };

        global.fetch.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ success: false, message: "unauthenticated user" })
        });

        const findings = await brokenAuthCheck(endpoint, mockContext);

        expect(global.fetch).toHaveBeenCalledOnce();
        expect(findings).toHaveLength(0); // A string alapú védelem megfogta
    });

    it('4. Sebezhetőség igazolása (High): A védett végpont token nélkül 200 OK-val kiszolgálta az adatot', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'GET',
            operation: {}
        };

        global.fetch.mockResolvedValue({
            status: 200,
            text: async () => JSON.stringify({ name: "Titkos Adat", balance: 1000 })
        });

        const findings = await brokenAuthCheck(endpoint, mockContext);

        // Ellenőrizzük, hogy a natív fetch a megfelelő paraméterekkel hívódott-e meg
        expect(global.fetch).toHaveBeenCalledWith(
            'http://test-api.local/api/users/user_123', // ID feloldva!
            expect.objectContaining({ method: 'GET' }) // Headers üres
        );

        expect(findings).toHaveLength(1);
        expect(findings[0].owaspCategory).toBe('API2:2023');
        expect(findings[0].severity).toBe('High');
        expect(findings[0].confidence).toBe('danger');
        expect(findings[0].description).toContain('hitelesítést ír elő, mégis token nélkül');
    });

    it('5. Gyanús viselkedés (Low): A védett végpont token nélkül nem 401/403, hanem pl. 500-as hibát dob', async () => {
        const endpoint = {
            path: '/api/users/{id}',
            method: 'DELETE',
            operation: {}
        };

        global.fetch.mockResolvedValue({
            status: 500,
            text: async () => "Internal Server Error"
        });

        const findings = await brokenAuthCheck(endpoint, mockContext);

        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe('Low');
        expect(findings[0].confidence).toBe('warning');
        expect(findings[0].description).toContain('500 státusszal válaszolt');
    });

    it('6. POST kérés esetén üres body-t kell küldenie, hogy ne body parse error-on bukjon el', async () => {
        const endpoint = {
            path: '/api/users',
            method: 'POST',
            operation: {}
        };

        global.fetch.mockResolvedValue({
            status: 401,
            text: async () => "Unauthorized"
        });

        await brokenAuthCheck(endpoint, mockContext);

        expect(global.fetch).toHaveBeenCalledWith(
            'http://test-api.local/api/users',
            expect.objectContaining({
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}) // Üres JSON objektum generálva!
            })
        );
    });
});