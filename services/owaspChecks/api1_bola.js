import { smartFetch } from '../smartFetch.js';


function generateMockPayloadFromSchema(schema) {
    if (!schema || !schema.properties) return {};
    const mock = {};
    for (const [key, prop] of Object.entries(schema.properties)) {
        if (prop.type === 'string') mock[key] = "bola_test_string";
        else if (prop.type === 'number' || prop.type === 'integer') mock[key] = 1;
        else if (prop.type === 'boolean') mock[key] = true;
        else if (prop.type === 'array') mock[key] = [];
        else mock[key] = "test"; // Fallback
    }
    return mock;
}

export async function checkApi1Bola(endpoint, context) {
    const findings = [];
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    // 1. RELEVANCIA VIZSGÁLAT
    const pathParamRegex = /{([^}]+)}/g;
    const match = pathParamRegex.exec(path);
    if (!match) return findings; 
    
    const paramName = match[1];

    // 2. ID KIKERESÉSE
    const pathParts = path.split('/').filter(Boolean);
    const paramIndex = pathParts.findIndex(part => part.includes('{'));
    let resourceCategory = '';
    
    for (let i = paramIndex - 1; i >= 0; i--) {
        if (harvestedIds[pathParts[i]] && harvestedIds[pathParts[i]].length > 0) {
            resourceCategory = pathParts[i];
            break;
        }
    }

    const validIds = harvestedIds[resourceCategory] || [];
    if (validIds.length === 0) return findings;

    // BIZTOSÍTÉK: Kizárjuk a tesztelő saját ismert adatait, hogy elkerüljük a Fals Pozitív riasztást!
    // (Feltételezzük, hogy a context.testerUserId tartalmazza a tester saját ID-ját)
    let targetId = validIds.find(id => id !== context.testerUserId);
    if (!targetId) targetId = validIds[0]; // Ha nincs más, kénytelenek vagyunk ezt használni

    const testPath = path.replace(`{${paramName}}`, targetId);
    const fullUrl = `${targetUrl}${testPath}`;

    try {
        const requestOptions = { 
            method: method.toUpperCase(),
            headers: {} 
        };

        let payloadStr = "";
        
        // 3. DINAMIKUS PAYLOAD GENERÁLÁS ADATMÓDOSÍTÓ KÉRÉSEKHEZ
        if (['POST', 'PUT', 'PATCH'].includes(requestOptions.method)) {
            const schema = operation.requestBody?.content?.['application/json']?.schema;
            const dynamicPayload = generateMockPayloadFromSchema(schema);
            
            payloadStr = JSON.stringify(dynamicPayload);
            requestOptions.body = payloadStr;
            requestOptions.headers['Content-Type'] = 'application/json';
        }

        // TÁMADÁS INDÍTÁSA a mezei tester tokennel
        const response = await smartFetch(fullUrl, requestOptions, context, 'tester');
        const status = response.status;
        
        // A válasz JSON kiolvasása a pontosabb heurisztikához
        let responseBody = "";
        try { responseBody = await response.text(); } catch (e) {}

        // 4. BOMBABIZTOS KIÉRTÉKELÉS
        
        // 400 Bad Request vagy 422 Unprocessable Entity esetén a teszt INCONCLUSIVE (Eredménytelen)
        if (status === 400 || status === 422) {
            console.warn(`[BOLA Warning] A ${path} végpont 400-as validációs hibát dobott. A BOLA nem igazolható, az API eldobta a formátumot.`);
            return findings;
        }

        if (status >= 200 && status < 300) {
            // "Ál-Sikeres" 200 OK szűrése: Ha a válaszban benne van, hogy error vagy unauthorized, az valójában védett!
            const bodyLower = responseBody.toLowerCase();
            if (bodyLower.includes('error') || bodyLower.includes('unauthorized') || bodyLower.includes('denied')) {
                return findings; // Fals pozitív megakadályozva
            }

            findings.push({
                owaspCategory: 'API1:2023',
                endpoint: path,
                method: method,
                severity: 'High',
                confidence: 'danger',
                description: `BOLA (IDOR) sebezhetőség igazolva. A jogosulatlan (tester) felhasználó teljes értékű hozzáférést/módosítási jogot kapott a(z) ${targetId} entitáshoz. (HTTP ${status})`,
                payloadUsed: payloadStr ? `Path: ${paramName}=${targetId} | Body: ${payloadStr}` : `Path: ${paramName}=${targetId}`
            });
        } 
        else if (status >= 500) {
            findings.push({
                owaspCategory: 'API1:2023',
                endpoint: path,
                method: method,
                severity: 'Medium',
                confidence: 'warning',
                description: `Szerver összeomlás (HTTP ${status}) egy idegen azonosító lekérésekor. Valószínűleg hiányzó objektumszintű jogosultság-ellenőrzés okozta a kivételt a kódban.`,
                payloadUsed: `Path paraméter: ${paramName}=${targetId}`
            });
        }
        
    } catch (error) {
        console.error(`[OWASP API1 Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    return findings;
}