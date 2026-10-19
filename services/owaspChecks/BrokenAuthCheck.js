/**
 * OWASP API2:2023 – Broken Authentication (hiányzó hitelesítés) teszt
 *
 * A modul azt vizsgálja, hogy egy hitelesítést elváró végpont token NÉLKÜL is
 * kiszolgál-e kérést. Ha igen, a hitelesítés megkerülhető.
 *
 * FONTOS: Ez a teszt szándékosan a natív `fetch`-et használja, NEM a smartFetch-et!
 * A smartFetch 401-nél automatikusan újrahitelesítene egy érvényes tokennel, ami
 * tönkretenné a tesztet (egy biztonságos végpontot is sebezhetőnek jelezne).
 * Itt pont az a lényeg, hogy SEMMILYEN token ne menjen a kérésre.
 *
 * @param {Object} endpoint Az aktuálisan vizsgált végpont adatai
 * @param {string} endpoint.path Az API útvonal (pl. "/api/users/{id}")
 * @param {string} endpoint.method HTTP metódus nagybetűvel (pl. "GET", "POST")
 * @param {Object} endpoint.operation A végpont OpenAPI leírása
 *
 * @param {Object} context A vizsgálat globális kontextusa
 * @param {string} context.targetUrl A vizsgált szerver alap URL-je
 * @param {Object} context.spec A teljes OpenAPI specifikáció
 * @param {Object} context.harvestedIds A Recon fázisban begyűjtött valid azonosítók
 *
 * @returns {Promise<Array<Object>>} A megtalált sebezhetőségek tömbje (üres, ha nincs találat)
 */
export async function brokenAuthCheck(endpoint, context) {
    // 1. Üres tömb a találatoknak (kötelező visszatérési érték)
    const findings = [];

    // 2. Szükséges adatok kinyerése
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    // --- 3. RELEVANCIA VIZSGÁLAT ---
    // Csak azokat a végpontokat nézzük, amelyek hitelesítést várnak el.
    const requiresAuth = endpointRequiresAuth(operation, context.spec);
    if (!requiresAuth) {
        return findings;
    }

    // --- 4. CÉLPONT ADATOK ELŐKÉSZÍTÉSE ---
    const resolvedPath = resolvePathParams(path, harvestedIds);
    const fullUrl = `${targetUrl.replace(/\/$/, '')}${resolvedPath}`;

    // --- 5. TÁMADÁS VÉGREHAJTÁSA: kérés token NÉLKÜL, natív fetch-csel ---
    try {
        const requestOptions = { method, headers: {} };

        // Ha a metódus törzset vár, egy üres JSON-t küldünk, hogy ne a hiányzó
        // body miatt kapjunk hibát, hanem tényleg a hitelesítés dőljön el.
        if (['POST', 'PUT', 'PATCH'].includes(method)) {
            requestOptions.body = JSON.stringify({});
            requestOptions.headers['Content-Type'] = 'application/json';
        }

        // Szándékosan NINCS Authorization fejléc, és NINCS smartFetch.
        const response = await fetch(fullUrl, requestOptions);

        // --- 6. KIÉRTÉKELÉS ÉS RIPORTÁLÁS ---
        if (response.status >= 200 && response.status < 300) {
            // Hitelesítést várt, mégis kiszolgált token nélkül → sebezhető
            findings.push({
                owaspCategory: 'API2:2023',
                endpoint: path,
                method: method,
                severity: 'High',
                confidence: 'danger',
                description: `A végpont hitelesítést ír elő, mégis token nélkül is ${response.status} státusszal válaszolt. A hitelesítés megkerülhető.`,
                payloadUsed: `${method} ${resolvedPath} (Authorization fejléc nélkül)`
            });
        } else if (response.status !== 401 && response.status !== 403) {
            // Nem 2xx, de nem is a várt 401/403 → gyanús, de csak figyelmeztetés
            findings.push({
                owaspCategory: 'API2:2023',
                endpoint: path,
                method: method,
                severity: 'Low',
                confidence: 'warning',
                description: `A végpont token nélkül nem 401/403, hanem ${response.status} státusszal válaszolt. Érdemes kézzel ellenőrizni a hitelesítés helyességét.`,
                payloadUsed: `${method} ${resolvedPath} (Authorization fejléc nélkül)`
            });
        }
        // 401 vagy 403 esetén a végpont helyesen védett → nincs találat.

    } catch (error) {
        console.error(`[API2 Modul Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    // 7. Visszatérés a találatokkal
    return findings;
}

/**
 * Megállapítja, hogy a végpont hitelesítést vár-e el.
 * Igaz, ha a műveletnek van nem üres security tömbje, vagy ha nincs sajátja,
 * de a specifikáció globálisan ír elő security-t.
 */
function endpointRequiresAuth(operation, spec) {
    if (Array.isArray(operation?.security)) {
        // Üres tömb ([]) kifejezetten kikapcsolja a hitelesítést erre a műveletre
        return operation.security.length > 0;
    }
    return Array.isArray(spec?.security) && spec.security.length > 0;
}

/**
 * Az útvonal {param} helyőrzőit kicseréli: ha a Recon talált hozzá valid ID-t,
 * azt használja, különben egy semleges minta értéket.
 */
function resolvePathParams(path, harvestedIds = {}) {
    return path.replace(/\{([^}]+)\}/g, (_, name) => {
        return harvestedIds?.[name] ?? '1';
    });
}