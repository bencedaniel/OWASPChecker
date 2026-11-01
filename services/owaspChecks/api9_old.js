import { smartFetch } from '../apiClient.js';

/**
 * OWASP API9:2023 – Improper Inventory Management (Nem megfelelő eszköz-/verziókezelés)
 * 
 * A modul azt vizsgálja, hogy az API tartalmaz-e elavult (deprecated) végpontokat,
 * vagy kihelyezett teszt/stég/régi verziós útvonalakat (pl. /v1/, /beta/, /test/),
 * amelyek elfelejtett, nem dokumentált támadási felületet biztosíthatnak.
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
export async function checkApi9ImproperInventory(endpoint, context) {
    // 1. Üres tömb inicializálása a találatoknak (Kötelező visszatérési érték)
    const findings = [];

    // 2. Szükséges adatok kinyerése a paraméterekből
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    const lowerPath = path.toLowerCase();

    // --- 3. RELEVANCIA VIZSGÁLAT ÉS TESZTELÉS ---

    // A) Ellenőrzés: Ha a specifikációban explicit deprecated, de a kód vizsgálja
    if (operation.deprecated === true) {
        findings.push({
            owaspCategory: 'API9:2023',
            endpoint: path,
            method: method,
            severity: 'Low',
            confidence: 'warning',
            description: `Improper Inventory Management: A végpont elavultként (deprecated) van jelölve a specifikációban, de még mindig része az aktív API felületnek.`,
            payloadUsed: `${method} ${path} (OpenAPI deprecated jelölés)`
        });
    }

    // B) Ellenőrzés: Elavult verziók vagy teszt/stég útvonalak keresése az URL-ben
    const legacyKeywords = ['/v1/', '/v0/', '/beta/', '/test/', '/old/', '/staging/', '/debug/', '/temp/'];
    const matchedKeyword = legacyKeywords.find(keyword => lowerPath.includes(keyword));

    if (matchedKeyword) {
        // Célpont útvonal feloldása (ha van benne {id})
        const resolvedPath = path.replace(/\{([^}]+)\}/g, (_, paramName) => {
            const pathParts = path.split('/').filter(Boolean);
            const paramIndex = pathParts.findIndex(part => part.includes('{'));
            let resourceCategory = paramIndex > 0 ? pathParts[paramIndex - 1] : '';
            const validIds = harvestedIds[resourceCategory] || [];
            return validIds.length > 0 ? validIds[0] : '1';
        });

        const fullUrl = `${targetUrl.replace(/\/$/, '')}${resolvedPath}`;

        try {
            // Megvizsgáljuk, hogy a régi/teszt végpont aktívan válaszol-e
            const response = await smartFetch(fullUrl, { method, headers: {} }, context, 'tester');
            
            if (response.status >= 200 && response.status < 400) {
                findings.push({
                    owaspCategory: 'API9:2023',
                    endpoint: path,
                    method: method,
                    severity: 'Medium',
                    confidence: 'warning',
                    description: `Improper Inventory Management: Az útvonal gyanús, elavult vagy teszt jellegű mintát tartalmaz ("${matchedKeyword}"), és a szerver aktívan kiszolgálja (HTTP ${response.status}).`,
                    payloadUsed: `${method} ${resolvedPath}`
                });
            }
        } catch (error) {
            // Ha hiba vagy elérés hiánya történik, azt figyelmen kívül hagyjuk (lehet, hogy már inaktív)
        }
    }

    // 7. Visszatérés a találatokkal (akár üres, akár tartalmaz hibát)
    return findings;
}