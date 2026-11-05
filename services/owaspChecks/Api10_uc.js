import { smartFetch } from '../apiClient.js';

/**
 * OWASP API10:2023 – Unsafe Consumption of APIs (Nem biztonságos API-fogyasztás)
 * 
 * A modul azt vizsgálja, hogy az API tartalmaz-e olyan külső integrációs, webhook
 * vagy callback végpontokat, amelyek harmadik fél szolgáltatásaival kommunikálnak,
 * és potenciálisan vakon bíznak a külső adatokban validáció nélkül.
 * 
 * @param {Object} endpoint Az aktuálisan vizsgált végpont adatai az OpenAPI specifikációból
 * @param {string} endpoint.path Az API útvonal (pl. "/api/users/{id}")
 * @param {string} endpoint.method HTTP metódus nagybetűvel (pl. "GET", "POST", "DELETE")
 * @param {Object} endpoint.operation A végpont részletes OpenAPI/Swagger leírása
 * 
 * @param {Object} context A vizsgálat globális kontextusa
 * @param {string} context.targetUrl A vizsgált szerver alap URL-je
 * @param {string} context.spec A teljes OpenAPI specifikáció
 * @param {string} context.adminToken Az adminisztrátori JWT token (ha van)
 * @param {string} context.testerToken A mezei felhasználói JWT token (ha van)
 * @param {Object} context.harvestedIds A Recon fázisban begyűjtött valid azonosítók szótára
 * 
 * @returns {Promise<Array<Object>>} Egy tömb, amely tartalmazza a megtalált sebezhetőségeket. 
 *                                   Ha nincs találat, KÖTELEZŐEN egy üres tömböt `[]` kell visszaadni!
 */
export async function checkApi10UnsafeConsumption(endpoint, context) {
    // 1. Üres tömb inicializálása a találatoknak (Kötelező visszatérési érték)
    const findings = [];

    // 2. Szükséges adatok kinyerése a paraméterekből
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    const upperMethod = method.toUpperCase();
    const lowerPath = path.toLowerCase();
    const summaryOrDesc = `${operation?.summary || ''} ${operation?.description || ''}`.toLowerCase();

    // --- 3. RELEVANCIA VIZSGÁLAT ---
    // Külső API fogyasztásra vagy webhookokra utaló kulcsszavak az útvonalban vagy leírásban
    const integrationKeywords = [
        'webhook', 'callback', 'external', 'sync', 'import', 
        'partner', 'integration', 'thirdparty', 'feed', 'upstream'
    ];

    const isIntegrationEndpoint = 
        integrationKeywords.some(keyword => lowerPath.includes(keyword)) ||
        integrationKeywords.some(keyword => summaryOrDesc.includes(keyword));

    if (!isIntegrationEndpoint) {
        return findings; // Ha nem integrációs végpont, átugorjuk
    }

    // --- 4. CÉLPONT ADATOK ELŐKÉSZÍTÉSE ---
    const resolvedPath = path.replace(/\{([^}]+)\}/g, (_, paramName) => {
        const pathParts = path.split('/').filter(Boolean);
        const paramIndex = pathParts.findIndex(part => part.includes('{'));
        let resourceCategory = paramIndex > 0 ? pathParts[paramIndex - 1] : '';
        const validIds = harvestedIds[resourceCategory] || [];
        return validIds.length > 0 ? validIds[0] : '1';
    });

    const fullUrl = `${targetUrl.replace(/\/$/, '')}${resolvedPath}`;

    // --- 5. VIZSGÁLAT VÉGREHAJTÁSA (smartFetch) ---
    try {
        // Külső integrációs / webhook végpontok tesztelése
        // Megvizsgáljuk, hogy a végpont él-e és fogad-e bejövő strukturált adatot
        const requestOptions = {
            method: upperMethod,
            headers: { 'Content-Type': 'application/json' },
        };

        if (['POST', 'PUT', 'PATCH'].includes(upperMethod)) {
            requestOptions.body = JSON.stringify({
                source: "security_scanner_probe",
                external_url: "http://untrusted-external-source.test",
                payload: "test_data"
            });
        }

        const response = await smartFetch(fullUrl, requestOptions, context, 'tester');
        const status = response.status;

        // --- 6. KIÉRTÉKELÉS ÉS RIPORTÁLÁS ---
        // Ha egy külső integrációs/webhook végpont hitelesítés nélkül vagy túl elnézően fogad adatot (2xx),
        // az arra utalhat, hogy a szerver validáció nélkül dolgozza fel a külső forrásokból származó adatokat.
        if (status >= 200 && status < 300) {
            findings.push({
                owaspCategory: 'API10:2023',
                endpoint: path,
                method: method,
                severity: 'Medium',
                confidence: 'warning',
                description: `Unsafe Consumption of APIs: Külső integrációs/webhook jellegű végpont ("${path}") észlelve, amely HTTP ${status} státusszal elfogadta a teszt adatcsomagot. Bizonyosodj meg róla, hogy a külső forrásból származó adatok szigorúan validálva és szűrve vannak.`,
                payloadUsed: `${method} ${resolvedPath} (integrációs próba)`
            });
        }

    } catch (error) {
        console.error(`[OWASP API10 Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    // 7. Visszatérés a találatokkal (akár üres, akár tartalmaz hibát)
    return findings;
}