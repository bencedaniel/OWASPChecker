import { smartFetch } from '../smartFetch.js';
export const SENSITIVE_KEYS_MULTILINGUAL = {
    // 1. Hitelesítési és titkosítási adatok
    credentials: {
        en: [
            'password', 'passwordHash', 'password_hash', 'pass', 'pwd', 'passwd',
            'secret', 'secretKey', 'api_secret', 'private_key', 'encryption_key',
            'salt', 'pepper', 'token', 'refreshToken', 'accessToken', 'jwt',
            'session_id', 'otp', 'pin', 'reset_token', 'verification_code'
        ],
        hu: [
            'jelszo', 'jelszó', 'jelszohash', 'jelszo_hash', 'titok', 'titkos_kulcs',
            'kulcs', 'privát_kulcs', 'so', 'salt_ertek', 'token', 'frissito_token',
            'munkamenet', 'pin_kod', 'visszaallito_token', 'aktivacios_kod'
        ],
        de: [
            'passwort', 'passworthash', 'passwort_hash', 'geheimnis', 'schluessel',
            'privater_schluessel', 'salz', 'token', 'sitzung', 'pin_code'
        ]
    },

    // 2. Jogosultsági és adminisztratív mezők
    authorization: {
        en: [
            'role', 'roles', 'user_role', 'account_type', 'permissions', 'privileges',
            'access_level', 'scopes', 'is_admin', 'isAdmin', 'is_superuser', 
            'is_staff', 'is_owner', 'is_root', 'is_active', 'is_verified'
        ],
        hu: [
            'szerepkor', 'szerepkör', 'szerep', 'felhasznaloi_szerep', 'fokozat',
            'jogosultsag', 'jogosultsagok', 'hozzaferesi_szint', 'admin', 'adminisztrator',
            'rendszergazda', 'tulajdonos', 'aktiv', 'ellenorzott'
        ],
        de: [
            'rolle', 'rollen', 'benutzerrolle', 'berechtigungen', 'privilegien',
            'zugriffslevel', 'administrator', 'eigentuemer', 'aktiv', 'verifiziert'
        ]
    },

    // 3. Belső metaadatok és technikai mezők
    metadata: {
        en: [
            '__v', 'internal_notes', 'admin_comment', 'debug_info', 'stack_trace',
            'deleted_at', 'is_deleted', 'server_ip', 'database_id'
        ],
        hu: [
            'belsomegjegyezes', 'admin_megjegyzes', 'hibakeresesi_info', 'torolve',
            'torles_datuma', 'szerver_ip', 'adatbazis_id'
        ],
        de: [
            'interne_notizen', 'admin_kommentar', 'debug_infos', 'gelaescht_am',
            'server_ip', 'datenbank_id'
        ]
    }
};
/**
 * Dinamikus "mérgezett" payload generátor OpenAPI séma alapján Mass Assignment teszthez.
 */
function generateDynamicMaliciousPayload(operation) {
    const schema = operation?.requestBody?.content?.['application/json']?.schema;
    const payload = {};

    if (schema && schema.properties) {
        for (const [key, prop] of Object.entries(schema.properties)) {
            if (prop.type === 'string') payload[key] = "test_value";
            else if (prop.type === 'number' || prop.type === 'integer') payload[key] = 1;
            else if (prop.type === 'boolean') payload[key] = false;
            else if (prop.type === 'array') payload[key] = [];
            else payload[key] = "test";
        }
    } else {
        payload.name = "BOPLA_Test";
    }

    const injectionVectors = [
        { key: 'isAdmin', value: true },
        { key: 'is_admin', value: true },
        { key: 'role', value: 'admin' },
        { key: 'roles', value: ['admin', 'superuser'] },
        { key: 'access_level', value: 99 },
        { key: 'permission', value: 'all' },
        { key: 'is_superuser', value: true }
    ];

    for (const vector of injectionVectors) {
        payload[vector.key] = vector.value;
    }

    return payload;
}

export async function checkApi3Bopla(endpoint, context) {
    const findings = [];
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    // Közös útvonal (path) paraméter feloldó segédfüggvény
    const resolvePath = (p) => {
        return p.replace(/\{([^}]+)\}/g, (_, paramName) => {
            const pathParts = p.split('/').filter(Boolean);
            const paramIndex = pathParts.findIndex(part => part.includes('{'));
            let resourceCategory = paramIndex > 0 ? pathParts[paramIndex - 1] : '';
            const validIds = harvestedIds[resourceCategory] || [];
            return validIds.length > 0 ? validIds[0] : '1';
        });
    };

    const resolvedPath = resolvePath(path);
    const fullUrl = `${targetUrl}${resolvedPath}`;

    try {
        // --- 1. GET ÁG: Excessive Data Exposure (Túlzott adatszivárgás) ---
        if (method.toUpperCase() === 'GET') {
            const response = await smartFetch(fullUrl, { method: 'GET' }, context, 'tester');
            
            if (response.status === 200) {
                const responseText = await response.text();
                let jsonData;
                try {
                    jsonData = JSON.parse(responseText);
                } catch (e) {
                    return findings; // Nem JSON válasz, átugorjuk
                }

                // Rekurzív kulcs-ellenőrzés a szótár alapján
                function findSensitiveKeys(obj, foundMatches = new Set()) {
                    if (!obj || typeof obj !== 'object') return foundMatches;

                    for (const [key, value] of Object.entries(obj)) {
                        const lowerKey = key.toLowerCase();

                        for (const [category, languages] of Object.entries(SENSITIVE_KEYS_MULTILINGUAL)) {
                            for (const [lang, words] of Object.entries(languages)) {
                                for (const word of words) {
                                    if (lowerKey === word.toLowerCase()) {
                                        foundMatches.add({ category, word, lang, keyFound: key });
                                    }
                                }
                            }
                        }

                        if (value && typeof value === 'object') {
                            findSensitiveKeys(value, foundMatches);
                        }
                    }
                    return foundMatches;
                }

                const sensitiveMatches = findSensitiveKeys(jsonData);

                for (const match of sensitiveMatches) {
                    findings.push({
                        owaspCategory: 'API3:2023',
                        endpoint: path,
                        method: method,
                        severity: 'Medium',
                        confidence: 'warning',
                        description: `Túlzott adatszivárgás (Excessive Data Exposure): A válasz JSON objektuma tartalmazza a(z) "${match.keyFound}" mezőt (${match.category}, kulcsszó: "${match.word}" [${match.lang}]).`,
                        payloadUsed: `GET ${resolvedPath}`
                    });
                }
            }
        } 
        
        // --- 2. NEM GET ÁG (POST, PUT, PATCH): Mass Assignment ---
        else if (['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
            const maliciousPayload = generateDynamicMaliciousPayload(operation);

            const response = await smartFetch(fullUrl, {
                method: method.toUpperCase(),
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(maliciousPayload)
            }, context, 'tester');

            if (response.status >= 200 && response.status < 300) {
                findings.push({
                    owaspCategory: 'API3:2023',
                    endpoint: path,
                    method: method,
                    severity: 'High',
                    confidence: 'warning',
                    description: `Potenciális Mass Assignment (API3) sebezhetőség. A szerver ${response.status} státusszal elfogadta a dinamikusan generált, jogosultság-emelő mezőket tartalmazó payloadot.`,
                    payloadUsed: JSON.stringify(maliciousPayload)
                });
            }
        }

    } catch (error) {
        console.error(`[OWASP API3 Hiba] A(z) ${path} vizsgálatakor:`, error.message);
    }

    return findings;
}