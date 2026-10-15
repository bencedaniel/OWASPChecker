/**
 * Végignézi az OpenAPI specifikációt, és megkeresi a bejelentkezési végpontot,
 * VALAMINT kinyeri, hogy a végpont milyen mezőneveket vár a felhasználónévhez és jelszóhoz.
 */
function findLoginEndpointInfo(spec) {
    if (!spec || !spec.paths) return null;

    for (const [path, methods] of Object.entries(spec.paths)) {
        if (methods.post) {
            const pathLower = path.toLowerCase();
            const operation = methods.post;

            let isLoginEndpoint = false;
            // Alapértelmezett feltételezések, ha nem találnánk mást
            let expectedUserKey = 'username'; 
            let expectedPassKey = 'password';

            // 1. Megnézzük az útvonal nevét
            if (pathLower.includes('/login') || pathLower.includes('/signin') || pathLower.includes('/auth')) {
                isLoginEndpoint = true;
            }

            // 2. Kielemezzük a Swagger által megadott paramétereket (Schema)
            try {
                const schema = operation.requestBody?.content['application/json']?.schema;
                if (schema && schema.properties) {
                    const props = Object.keys(schema.properties);
                    
                    // Kikeressük a jelszó mező pontos nevét (lehet 'password', 'pass', 'pin', stb.)
                    const foundPassKey = props.find(k => k.toLowerCase().includes('pass') || k.toLowerCase().includes('pin'));
                    if (foundPassKey) {
                        expectedPassKey = foundPassKey;
                        isLoginEndpoint = true; // Ha van jelszó mező, az nagyon erős bizonyíték, hogy ez egy login
                    }

                    // Kikeressük a felhasználónév mező pontos nevét (lehet 'email', 'username', 'login', 'identifier')
                    const foundUserKey = props.find(k => 
                        k.toLowerCase().includes('email') || 
                        k.toLowerCase().includes('user') || 
                        k.toLowerCase().includes('login')
                    );
                    if (foundUserKey) {
                        expectedUserKey = foundUserKey;
                    }
                }
            } catch (error) {
                // Ha a schema nem olvasható, megyünk tovább
            }

            // Ha beazonosítottuk, hogy ez a login végpont, visszaadjuk a pontos paraméternevekkel együtt
            if (isLoginEndpoint) {
                return { 
                    path, 
                    usernameKey: expectedUserKey, 
                    passwordKey: expectedPassKey 
                };
            }
        }
    }

    return null;
}

/**
 * Dinamikusan belép a célrendszerbe. A payload struktúráját a Swagger specifikáció 
 * alapján dinamikusan építi fel.
 */
export async function getAuthToken(targetUrl, credentials, openApiSpec) {
    if (!credentials || !credentials.username || !credentials.password) {
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
    requestBody[loginInfo.usernameKey] = credentials.username;
    requestBody[loginInfo.passwordKey] = credentials.password;

    console.log(`[Auth] Belépés: ${loginInfo.path} | Használt séma: { "${loginInfo.usernameKey}": "...", "${loginInfo.passwordKey}": "..." }`);

    try {
        const response = await fetch(fullLoginUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody) // A dinamikusan felépített JSON-t küldjük
        });

        if (!response.ok) {
            console.error(`[Auth] Sikertelen bejelentkezés (${response.status}) a '${credentials.username}' fiókkal.`);
            return null;
        }

        const data = await response.json();
        
        // A token kulcsa általában 'token' vagy 'accessToken'
        return data.token || data.accessToken || data.access_token || null; 
    } catch (error) {
        console.error(`[Auth] Hálózati hiba a bejelentkezéskor:`, error.message);
        return null;
    }
}

/**
 * Felderíti az API-t a megadott OpenAPI specifikáció alapján, listázza a végpontokat,
 * és kinyeri a létező azonosítókat a későbbi sebezhetőség vizsgálatokhoz.
 */
export async function harvestResourceIds(targetUrl, openApiSpec, adminToken) {
    const harvestedData = {}; 

    const fetchOptions = {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${adminToken}`,
            'Accept': 'application/json'
        }
    };

    for (const [path, methods] of Object.entries(openApiSpec.paths || {})) {
        if (methods.get && !path.includes('{')) {
            const fullUrl = `${targetUrl}${path}`;
            const pathParts = path.split('/').filter(Boolean);
            const resourceName = pathParts[pathParts.length - 1];
            
            if (!harvestedData[resourceName]) {
                harvestedData[resourceName] = [];
            }

            try {
                const response = await fetch(fullUrl, fetchOptions);
                if (response.ok) {
                    const data = await response.json();
                    
                    if (Array.isArray(data)) {
                        data.forEach(item => {
                            if (item._id) harvestedData[resourceName].push(item._id);
                            if (item.id) harvestedData[resourceName].push(item.id);
                        });
                    } else if (typeof data === 'object' && data !== null) {
                        Object.values(data).forEach(val => {
                            if (Array.isArray(val)) {
                                val.forEach(item => {
                                    if (item._id) harvestedData[resourceName].push(item._id);
                                });
                            }
                        });
                    }
                }
            } catch (error) {
                console.warn(`[Recon] Hiba a ${path} felderítésekor:`, error.message);
            }
        }
    }

    for (const key in harvestedData) {
        harvestedData[key] = [...new Set(harvestedData[key])];
    }

    return harvestedData;
}