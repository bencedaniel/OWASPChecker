import { smartFetch } from '../smartFetch.js';
import { resolvePathParams } from '../pathResolver.js';

/**
 * OWASP API8:2023 – Security Misconfiguration (Biztonsági hibás konfigurációk)
 * 
 * A modul azt vizsgálja, hogy az API válaszai tartalmaznak-e hiányzó biztonsági fejléceket,
 * veszélyes CORS beállításokat, vagy olyan részletes hibajelzéseket (stack trace / debug info),
 * amelyek helytelen konfigurációra utalnak.
 * 
 * @param {Object} endpoint Az aktuálisan vizsgált végpont adatai az OpenAPI specifikációból
 * @param {string} endpoint.path Az API útvonal (pl. "/api/users/{id}")
 * @param {string} endpoint.method HTTP metódus nagybetűvel (pl. "GET", "POST", "DELETE")
 * @param {Object} endpoint.operation A végpont részletes OpenAPI/Swagger leírása
 * 
 * @param {Object} context A vizsgálat globális kontextusa
 * @param {string} context.targetUrl A vizsgált szerver alap URL-je
 * @param {Object} context.spec A teljes OpenAPI specifikáció
 * @param {string} context.adminToken Az adminisztrátori JWT token (ha van)
 * @param {string} context.testerToken A mezei felhasználói JWT token (ha van)
 * @param {Object} context.harvestedIds A Recon fázisban begyűjtött valid azonosítók szótára
 * 
 * @returns {Promise<Array<Object>>} Egy tömb, amely tartalmazza a megtalált sebezhetőségeket. 
 *                                   Ha nincs találat, KÖTELEZŐEN egy üres tömböt `[]` kell visszaadni!
 */
export async function checkApi8SecurityMisconfiguration(endpoint, context) {
    // 1. Üres tömb inicializálása a találatoknak (Kötelező visszatérési érték)
    const findings = [];

    // 2. Szükséges adatok kinyerése a paraméterekből
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    if (method.toUpperCase() === 'DELETE' && /(^|\/)me(\/|$)/i.test(path)) {
        return findings;
    }

    // --- 3. RELEVANCIA VIZSGÁLAT ---
    // A Security Misconfiguration minden végponton vizsgálható, de leginkább GET 
    // kéréseknél vagy általános OPTIONS/szándékos hibakezelési teszteknél mutatja meg magát.
    // Nem szűrjük ki a path-t, mert a globális fejeceket és hibakezelést mindenhol vizsgálni kell.

    // --- 4. CÉLPONT ADATOK ELŐKÉSZÍTÉSE ---
// --- 4. CÉLPONT ADATOK ELŐKÉSZÍTÉSE ---
    const resolvedPath = resolvePathParams(path, harvestedIds);
    if (!resolvedPath) return findings;

    const fullUrl = `${targetUrl.replace(/\/$/, '')}${resolvedPath}`;

    // --- 5. TÁMADÁS / VIZSGÁLAT VÉGREHAJTÁSA (smartFetch) ---
    try {
        // A) Normál kérés a fejlécek és a normál válasz vizsgálatához
        const response = await smartFetch(fullUrl, { method, headers: {} }, context, 'tester');
        
        let responseBody = "";
        try { responseBody = await response.text(); } catch (e) {}

        const headers = response.headers;

        // --- 6. KIÉRTÉKELÉS ÉS RIPORTÁLÁS ---

        // 1. Teszt: Hiányzó fontos biztonsági HTTP fejecek (Security Headers)
        const missingHeaders = [];
        if (!headers.get('x-content-type-options')) missingHeaders.push('X-Content-Type-Options');
        if (!headers.get('x-frame-options')) missingHeaders.push('X-Frame-Options');
        if (!headers.get('strict-transport-security') && targetUrl.startsWith('https')) {
            missingHeaders.push('Strict-Transport-Security (HSTS)');
        }

        if (missingHeaders.length >= 2) {
            findings.push({
                owaspCategory: 'API8:2023',
                endpoint: path,
                method: method,
                severity: 'Low',
                confidence: 'warning',
                description: `Security Misconfiguration: A válaszból hiányoznak a fontos biztonsági HTTP fejecek: ${missingHeaders.join(', ')}.`,
                payloadUsed: `${method} ${resolvedPath} (fejléc elemzés)`
            });
        }

        // 2. Teszt: Veszélyes CORS beállítás (Access-Control-Allow-Origin: *)
        const corsOrigin = headers.get('access-control-allow-origin');
        const corsCredentials = headers.get('access-control-allow-credentials');
        
        if (corsOrigin === '*' && corsCredentials === 'true') {
            findings.push({
                owaspCategory: 'API8:2023',
                endpoint: path,
                method: method,
                severity: 'High',
                confidence: 'danger',
                description: `Kritikus CORS hibás konfiguráció: Az API engedélyezi a wildcard origin-t (*) a hitelesített kéréseknél (Access-Control-Allow-Credentials: true). Ez adatszivárgáshoz vezethet!`,
                payloadUsed: `${method} ${resolvedPath} (CORS vizsgálat)`
            });
        }

        // 3. Teszt: Stack trace vagy részletes hibaüzenet szivárgás szándékos rossz kéréssel
        // Küldünk egy direkt rossz formátumú/szándékosan hibás kérést, hogy lássuk, mit felel a szerver hiba esetén
        const badRequest = {
            method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (!['GET', 'HEAD'].includes(method.toUpperCase())) {
            badRequest.body = JSON.stringify({ invalid_malformed_test_key_xyz: "trigger_error" });
        }
        const badResponse = await smartFetch(fullUrl, badRequest, context, 'tester');

        let badResponseBody = "";
        try { badResponseBody = await badResponse.text(); } catch (e) {}
        
        const bodyLower = badResponseBody.toLowerCase();
        const hasStackTrace = 
            bodyLower.includes('at object.') || 
            bodyLower.includes('at module.') || 
            bodyLower.includes('stacktrace') || 
            bodyLower.includes('sqlsyntaxerror') ||
            bodyLower.includes('traceback (most recent call last)');

        if (hasStackTrace) {
            findings.push({
                owaspCategory: 'API8:2023',
                endpoint: path,
                method: method,
                severity: 'Medium',
                confidence: 'danger',
                description: `Információ-szivárgás (Stack Trace Disclosure): A szerver hiba esetén részletes technológiai nyomvonalat (stack trace) adott vissza, ami segít a támadónak feltérképezni a belső környezetet.`,
                payloadUsed: `${method} ${resolvedPath} (hibás törzs küldése)`
            });
        }

    } catch (error) {
        console.error(`[OWASP API8 Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    // 7. Visszatérés a találatokkal (akár üres, akár tartalmaz hibát)
    return findings;
}