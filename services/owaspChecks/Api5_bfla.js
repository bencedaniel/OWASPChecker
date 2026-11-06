import { smartFetch } from '../smartFetch.js';

function getCategories(harvestedIds) {
    return harvestedIds?.categories || harvestedIds || {};
}

function findIdsForSegment(segment, categories) {
    const categoryKey = Object.keys(categories).find(
        key => key.toLowerCase() === segment.toLowerCase()
    );
    return categoryKey && Array.isArray(categories[categoryKey])
        ? categories[categoryKey]
        : [];
}

function getCandidatePaths(path, harvestedIds) {
    const pathParts = path.split('/').filter(Boolean);
    const parameterIndexes = pathParts
        .map((part, index) => part.match(/^\{([^}]+)\}$/) ? index : -1)
        .filter(index => index !== -1);

    if (parameterIndexes.length === 0) return [path];

    const categories = getCategories(harvestedIds);
    const idsByParameter = parameterIndexes.map(parameterIndex => {
        for (let resourceIndex = parameterIndex - 1; resourceIndex >= 0; resourceIndex--) {
            const ids = findIdsForSegment(pathParts[resourceIndex], categories);
            if (ids.length > 0) return ids;
        }
        return [];
    });

    if (idsByParameter.some(ids => ids.length === 0)) return [];

    return idsByParameter.reduce(
        (paths, ids, parameterIndex) => paths.flatMap(currentPaths =>
            ids.map(id => currentPaths.map(pathPartsForCurrentPath => {
                const parts = pathPartsForCurrentPath.split('/').filter(Boolean);
                parts[parameterIndexes[parameterIndex]] = String(id);
                return `/${parts.join('/')}`;
            }))
        ),
        [[path]]
    ).flat().slice(0, 50);
}
/**
 * OWASP API5:2023 – Broken Function Level Authorization (BFLA) teszt
 * 
 * A modul azt vizsgálja, hogy egy korlátozott jogosultságú felhasználó ('tester')
 * képes-e meghívni olyan adminisztratív vagy emelt szintű funkciókat/végpontokat,
 * amelyekhez elvileg nincsenek jogai.
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
export async function checkApi5Bfla(endpoint, context) {
    // 1. Üres tömb inicializálása a találatoknak (Kötelező visszatérési érték)
    const findings = [];

    // 2. Szükséges adatok kinyerése a paraméterekből
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds, spec } = context;

    // --- 3. RELEVANCIA VIZSGÁLAT ---
    // A) Csak azokat a végpontokat vizsgáljuk, amelyek neve/útvonala adminisztratív jellegű
    const lowerPath = path.toLowerCase();
    const isAdminPath = lowerPath.includes('admin') || 
                        lowerPath.includes('manage') || 
                        lowerPath.includes('dashboard') || 
                        lowerPath.includes('config') || 
                        lowerPath.includes('settings');

    if (!isAdminPath) {
        return findings;
    }

    // B) Kiszűrjük a publikus végpontokat (ha eleve bárki elérheti, az nem BFLA)
    const localSecurity = operation.security;
    const globalSecurity = spec?.security;
    const isPublic = (localSecurity !== undefined && localSecurity.length === 0) || 
                     (!localSecurity && (!globalSecurity || globalSecurity.length === 0));

    if (isPublic) {
        return findings;
    }

    // --- 4. CÉLPONT ADATOK ELŐKÉSZÍTÉSE ---
    // Az útvonal paraméterek helyettesítése alapértelmezett '1'-el vagy Recon azonosítóval
// --- 4. CÉLPONT ADATOK ELŐKÉSZÍTÉSE ---
    const candidatePaths = getCandidatePaths(path, harvestedIds);
    if (candidatePaths.length === 0) return findings;

    // --- 5. TÁMADÁS VÉGREHAJTÁSA (smartFetch) ---
    try {
        const requestOptions = { method, headers: {} };

        // Ha a metódus törzset vár, küldünk egy üres JSON objektumot
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
            requestOptions.body = JSON.stringify({});
            requestOptions.headers['Content-Type'] = 'application/json';
        }

        for (const resolvedPath of candidatePaths) {
            const fullUrl = `${targetUrl.replace(/\/$/, '')}${resolvedPath}`;
            const response = await smartFetch(fullUrl, requestOptions, context, 'tester');
            const status = response.status;

            if (status === 404) {
                console.log(`[API5] ${resolvedPath} nem található (404), következő begyűjtött ID próbálata.`);
                continue;
            }

            // --- 6. KIÉRTÉKELÉS ÉS RIPORTÁLÁS ---
            // Ha a mezei felhasználó 2xx sikeres választ kapott az admin végpontra -> BFLA sebezhetőség
            if (status >= 200 && status < 300) {
                let responseBody = "";
                try { responseBody = await response.text(); } catch (e) {}

                // Fals pozitív szűrés (ha a 200 OK státusz ellenére a válasz hibaüzenetet tartalmaz)
                const bodyLower = responseBody.toLowerCase();
                if (bodyLower.includes('error') || bodyLower.includes('unauthorized') || bodyLower.includes('forbidden')) {
                    return findings;
                }

                findings.push({
                    owaspCategory: 'API5:2023',
                    endpoint: path,
                    method: method,
                    severity: 'High',
                    confidence: 'danger',
                    description: `Broken Function Level Authorization (BFLA) sebezhetőség. Egy korlátozott jogosultságú ('tester') felhasználó sikeresen meghívta az adminisztratív végpontot (HTTP ${status}).`,
                    payloadUsed: `${method} ${resolvedPath} (tester tokennel)`
                });
            }

            return findings;
        }

    } catch (error) {
        console.error(`[OWASP API5 BFLA Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    // 7. Visszatérés a találatokkal (akár üres, akár tartalmaz hibát)
    return findings;
}