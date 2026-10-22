import { smartFetch } from '../apiClient.js';

/**
 * OWASP API4:2023 – Unrestricted Resource Consumption (Rate Limiting hiánya) teszt
 * 
 * A modul azt vizsgálja, hogy egy adott végpont korlátozza-e a gyors egymás után 
 * érkező kérések számát (Rate Limiting / Throttling védelem).
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
export async function checkApi4RateLimit(endpoint, context) {
    // 1. Üres tömb inicializálása a találatoknak (Kötelező visszatérési érték)
    const findings = [];

    // 2. Szükséges adatok kinyerése a paraméterekből
    const { path, method } = endpoint;
    const { targetUrl, harvestedIds } = context;

    // --- 3. RELEVANCIA VIZSGÁLAT ---
    // A Rate Limiting tesztelés mindegyik metódusra (főleg GET és POST) releváns,
    // de célszerű a publikus vagy hitelesítést igénylő főbb végpontokon futtatni.
    // Nem releváns, ha a végpont eleve dokumentáltan belső vagy teszt jellegű.
    const lowerPath = path.toLowerCase();
    if (lowerPath.includes('health') || lowerPath.includes('ping')) {
        return findings; // Az egészségellenőrző végpontokat felesleges terhelni
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

    // --- 5. TÁMADÁS VÉGREHAJTÁSA (smartFetch) ---
    try {
        const requestOptions = { method, headers: {} };

        if (['POST', 'PUT', 'PATCH'].includes(method)) {
            requestOptions.body = JSON.stringify({});
            requestOptions.headers['Content-Type'] = 'application/json';
        }

        // Többszörös (sorozatos) kérés küldése a rate limit kiváltásához
        // (Általában 8-10 gyors kérés már el kell indítson egy védelemet egy védett API-n)
        const burstCount = 30;
        let receivedRateLimit = false;
        let lastStatus = null;

        for (let i = 0; i < burstCount; i++) {
            // A tesztet a 'tester' tokennel futtatjuk
            const response = await smartFetch(fullUrl, requestOptions, context, 'tester');
            lastStatus = response.status;

            // Ha a szerver 429 Too Many Requests-el válaszol, vagy rate limit fejlécet ad, akkor van védelem!
            if (response.status === 429 || response.headers.get('retry-after') || response.headers.get('x-ratelimit-remaining') === '0') {
                receivedRateLimit = true;
                break;
            }

            // Nagyon rövid szünet a kérések között, hogy ne terheljük túl a saját tesztszerverünket, de mégis "burst" legyen
            await new Promise(resolve => setTimeout(resolve, 50));
        }

        // --- 6. KIÉRTÉKELÉS ÉS RIPORTÁLÁS ---
        // Ha az összes kérés simán lement (pl. mind 200 OK vagy 201), és egyszer sem kaptunk 429-et -> Hiányzik a Rate Limiting
        if (!receivedRateLimit && lastStatus >= 200 && lastStatus < 300) {
            findings.push({
                owaspCategory: 'API4:2023',
                endpoint: path,
                method: method,
                severity: 'Medium',
                confidence: 'warning',
                description: `Unrestricted Resource Consumption (Hiányzó Rate Limiting): A végpont ${burstCount} gyors egymás utáni kérést is korlátozás nélkül kiszolgált (HTTP ${lastStatus}, nincs 429 válasz).`,
                payloadUsed: `${burstCount}x ${method} ${resolvedPath} sorozatos kérés`
            });
        }

    } catch (error) {
        console.error(`[OWASP API4 Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    // 7. Visszatérés a találatokkal (akár üres, akár tartalmaz hibát)
    return findings;
}