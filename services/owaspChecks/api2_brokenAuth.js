import { resolvePathParams } from '../pathResolver.js';

/**
 * OWASP API2:2023 – Broken Authentication átfogó ellenőrzés:
 * 1. Védett végpontok elérése token nélkül (natív fetch, smartFetch megkerülésével).
 * 2. Bejelentkezési (login) végpontok brute-force / rate-limit / account lockout hiányának vizsgálata.
 * 3. Sikeres bejelentkezésnél visszaadott JWT token lejárati idejének (TTL) ellenőrzése.
 *
 * @param {Object} endpoint Az aktuálisan vizsgált végpont adatai
 * @param {string} endpoint.path Az API útvonal (pl. "/api/auth/login", "/api/users/{id}")
 * @param {string} endpoint.method HTTP metódus nagybetűvel (pl. "GET", "POST")
 * @param {Object} endpoint.operation A végpont OpenAPI leírása
 *
 * @param {Object} context A vizsgálat globális kontextusa
 * @param {string} context.targetUrl A vizsgált szerver alap URL-je
 * @param {Object} context.spec A teljes OpenAPI specifikáció
 * @param {Object} context.harvestedIds A Recon fázisban begyűjtött valid azonosítók
 * @param {Object} [context.credentials] Opcionális hitelesítő adatok ({ user, admin })
 * @param {Object} [context.testUserCredentials] Opcionális teszt felhasználó ({ username/email, password })
 * @param {Object} [context.testAdminCredentials] Opcionális teszt admin ({ username/email, password })
 *
 * @returns {Promise<Array<Object>>} A megtalált sebezhetőségek tömbje
 */
export async function brokenAuthCheck(endpoint, context) {
    const findings = [];
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds, spec } = context;

    if (method.toUpperCase() === 'DELETE' && context.allowDestructive !== true) {
        return findings;
    }

    const baseUrl = targetUrl.replace(/\/$/, '');

    // --- 1. TOKEN NÉLKÜLI HITELESÍTÉS-MEGKERÜLÉS VIZSGÁLATA ---
    const requiresAuth = endpointRequiresAuth(operation, spec);
    if (requiresAuth) {
        const resolvedPath = resolvePathParams(path, harvestedIds);
        if (resolvedPath) {
            const fullUrl = `${baseUrl}${resolvedPath}`;
            try {
                const requestOptions = { method, headers: {} };

                if (['POST', 'PUT', 'PATCH'].includes(method)) {
                    requestOptions.body = JSON.stringify({});
                    requestOptions.headers['Content-Type'] = 'application/json';
                }

                // Szándékosan natív fetch Authorization fejléc és smartFetch nélkül
                const response = await fetch(fullUrl, requestOptions);

                let responseBody = '';
                try {
                    responseBody = await response.text();
                } catch (_) {}

                if (response.status >= 200 && response.status < 300) {
                    const bodyLower = responseBody.toLowerCase();
                    const looksLikeAuthError =
                        bodyLower.includes('error') ||
                        bodyLower.includes('unauthorized') ||
                        bodyLower.includes('denied') ||
                        bodyLower.includes('unauthenticated');

                    if (!looksLikeAuthError) {
                        findings.push({
                            owaspCategory: 'API2:2023',
                            endpoint: path,
                            method,
                            severity: 'High',
                            confidence: 'danger',
                            description: `A végpont hitelesítést ír elő, mégis token nélkül is ${response.status} státusszal válaszolt. A hitelesítés megkerülhető.`,
                            payloadUsed: `${method} ${resolvedPath} (Authorization fejléc nélkül)`
                        });
                    }
                } else if (response.status !== 401 && response.status !== 403) {
                    findings.push({
                        owaspCategory: 'API2:2023',
                        endpoint: path,
                        method,
                        severity: 'Low',
                        confidence: 'warning',
                        description: `A végpont token nélkül nem 401/403, hanem ${response.status} státusszal válaszolt. Érdemes kézzel ellenőrizni a hitelesítés helyességét.`,
                        payloadUsed: `${method} ${resolvedPath} (Authorization fejléc nélkül)`
                    });
                }
            } catch (error) {
                console.error(`[API2 Modul Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
            }
        }
    }

    // --- 2. LOGIN VÉGPONT: BRUTE-FORCE / RATE-LIMIT / LOCKOUT ÉS JWT TTL ---
    if (method === 'POST' && /login/i.test(path)) {
        const loginFindings = await checkLoginEndpointWeaknesses(path, method, baseUrl, context);
        findings.push(...loginFindings);
    }

    return findings;
}

/**
 * Megvizsgálja, hogy a login végpont védve van-e ismételt sikertelen kísérletekkel szemben,
 * és ellenőrzi a sikeres belépéskor kapott JWT token lejárati idejét.
 */
async function checkLoginEndpointWeaknesses(path, method, baseUrl, context) {
    const findings = [];
    const fullUrl = `${baseUrl}${path}`;

    const userCreds = context.credentials?.user || context.testUserCredentials;
    const adminCreds = context.credentials?.admin || context.testAdminCredentials;

    const probeEmail =
        userCreds?.email ||
        userCreds?.username ||
        adminCreds?.email ||
        adminCreds?.username ||
        'test@mail.hu';

    const attempts = 12;
    let rateLimitedOrLocked = false;
    let unexpectedStatus = null;

    for (let i = 0; i < attempts; i++) {
        try {
            const response = await fetch(fullUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: probeEmail,
                    password: `invalid_probe_${i}_${Date.now()}`
                })
            });

            const bodyText = await response.text().catch(() => '');
            const bodyLower = bodyText.toLowerCase();

            if (
                response.status === 429 ||
                bodyLower.includes('rate limit') ||
                bodyLower.includes('too many requests') ||
                bodyLower.includes('locked') ||
                bodyLower.includes('lockout') ||
                bodyLower.includes('zárol')
            ) {
                rateLimitedOrLocked = true;
                break;
            }

            if (response.status !== 401 && unexpectedStatus === null) {
                unexpectedStatus = response.status;
            }
        } catch (error) {
            console.error(`[API2 Login Modul Hiba] ${path} (brute-force teszt):`, error.message);
            break;
        }
    }

    if (!rateLimitedOrLocked) {
        findings.push({
            owaspCategory: 'API2:2023',
            endpoint: path,
            method,
            severity: 'Medium',
            confidence: 'warning',
            description: `A bejelentkezési végpont ${attempts} gyors, hibás jelszavas kérés után sem alkalmazott rate limitinget (HTTP 429) vagy fiókzárolást, így brute-force támadásnak lehet kitéve.`,
            payloadUsed: `${attempts}x POST ${path} hibás jelszóval (email: ${probeEmail})`
        });
    }

    if (unexpectedStatus !== null) {
        findings.push({
            owaspCategory: 'API2:2023',
            endpoint: path,
            method,
            severity: 'Low',
            confidence: 'warning',
            description: `A sikertelen bejelentkezési kérés 401 helyett ${unexpectedStatus} státuszkódot adott vissza.`,
            payloadUsed: `POST ${path} hibás jelszóval (email: ${probeEmail})`
        });
    }

    // JWT lejárati idő (exp - iat) ellenőrzése valid teszt hitelesítő adatokkal
    const validCreds = userCreds || adminCreds;
    const validIdentifier = validCreds?.email || validCreds?.username;
    if (validIdentifier && validCreds?.password) {
        try {
            const response = await fetch(fullUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    email: validIdentifier,
                    password: validCreds.password
                })
            });

            if (response.ok) {
                const data = await response.json().catch(() => null);
                const ttlSeconds = extractJwtTtlSeconds(data?.token);

                // 3600 másodperc (1 óra) feletti élettartamot hosszú lejáratként jelöljük
                const maxRecommendedTtlSeconds = 3600;
                if (typeof ttlSeconds === 'number' && ttlSeconds > maxRecommendedTtlSeconds) {
                    const hours = Math.round((ttlSeconds / 3600) * 10) / 10;
                    findings.push({
                        owaspCategory: 'API2:2023',
                        endpoint: path,
                        method,
                        severity: 'Low',
                        confidence: 'warning',
                        description: `A bejelentkezéskor kiadott JWT token élettartama (${ttlSeconds} mp / ~${hours} óra) meghaladja az ajánlott 1 órát, ami növeli a visszaélés kockázatát.`,
                        payloadUsed: `POST ${path} (JWT exp - iat elemzés)`
                    });
                }
            }
        } catch (error) {
            console.error(`[API2 Login Modul Hiba] ${path} (JWT TTL teszt):`, error.message);
        }
    }

    return findings;
}

/**
 * Aláírás-ellenőrzés nélkül dekódolja a JWT payloadot, és visszaadja az (exp - iat) értéket másodpercben.
 */
function extractJwtTtlSeconds(token) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    try {
        const base64Url = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64Url.padEnd(base64Url.length + ((4 - (base64Url.length % 4)) % 4), '=');
        const payloadJson = Buffer.from(padded, 'base64').toString('utf8');
        const payload = JSON.parse(payloadJson);

        if (typeof payload.exp === 'number' && typeof payload.iat === 'number') {
            return payload.exp - payload.iat;
        }
    } catch (_) {
        return null;
    }

    return null;
}

/**
 * Megállapítja, hogy a végpont hitelesítést vár-e el.
 * Igaz, ha a műveletnek van nem üres security tömbje, vagy ha nincs sajátja,
 * de a specifikáció globálisan ír elő security-t.
 */
function endpointRequiresAuth(operation, spec) {
    if (Array.isArray(operation?.security)) {
        return operation.security.length > 0;
    }
    return Array.isArray(spec?.security) && spec.security.length > 0;
}