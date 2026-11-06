import { smartFetch } from '../smartFetch.js';
import { resolvePathParamCandidates } from '../pathResolver.js';

function resolveSchema(schema, spec, seen = new Set()) {
    if (!schema || typeof schema !== 'object') return null;
    if (!schema.$ref) return schema;

    const match = schema.$ref.match(/^#\/components\/schemas\/([^/]+)$/);
    if (!match || seen.has(match[1])) return null;
    seen.add(match[1]);
    return resolveSchema(spec?.components?.schemas?.[match[1]], spec, seen);
}

function generateMockValue(schema, spec) {
    const resolved = resolveSchema(schema, spec);
    if (!resolved) return 'bola_test_string';
    if (resolved.example !== undefined) return resolved.example;
    if (resolved.default !== undefined) return resolved.default;
    if (Array.isArray(resolved.enum) && resolved.enum.length > 0) return resolved.enum[0];
    if (resolved.format === 'email') return 'bola-test@example.invalid';
    if (resolved.type === 'string') return 'bola_test_string';
    if (resolved.type === 'number' || resolved.type === 'integer') return 1;
    if (resolved.type === 'boolean') return true;
    if (resolved.type === 'array') return [];
    if (resolved.type === 'object' || resolved.properties) {
        return generateMockPayloadFromSchema(resolved, spec);
    }
    return 'test';
}

function generateMockPayloadFromSchema(schema, spec) {
    const resolvedSchema = resolveSchema(schema, spec);
    if (!resolvedSchema) return {};

    if (resolvedSchema.allOf) {
        return resolvedSchema.allOf.reduce(
            (payload, part) => ({ ...payload, ...generateMockPayloadFromSchema(part, spec) }),
            {}
        );
    }

    if (!resolvedSchema.properties) return {};

    const mock = {};
    for (const [key, prop] of Object.entries(resolvedSchema.properties)) {
        mock[key] = generateMockValue(prop, spec);
    }
    return mock;
}

export async function checkApi1Bola(endpoint, context) {
    const findings = [];
    const { path, method, operation } = endpoint;
    const { targetUrl } = context;

    // 1. RELEVANCIA VIZSGÁLAT
    const pathParamRegex = /{([^}]+)}/g;
    const match = pathParamRegex.exec(path);
    if (!match) return findings; 
    
    const paramName = match[1];

    // 2. ID KIKERESÉSE (Szigorúan kategória alapján)
    const candidatePaths = resolvePathParamCandidates(path, context.harvestedIds);
    if (candidatePaths.length === 0) return findings;

    try {
        let lastValidationStatus = null;
        for (const testPath of candidatePaths) {
            const requestOptions = { method: method.toUpperCase(), headers: {} };
            let payloadStr = "";
            const schema = operation.requestBody?.content?.['application/json']?.schema;

            if (['POST', 'PUT', 'PATCH'].includes(requestOptions.method) && schema) {
                const dynamicPayload = generateMockPayloadFromSchema(schema, context.spec);
                payloadStr = JSON.stringify(dynamicPayload);
                requestOptions.body = payloadStr;
                requestOptions.headers['Content-Type'] = 'application/json';
            }

            const response = await smartFetch(
                `${targetUrl.replace(/\/$/, '')}${testPath}`,
                requestOptions,
                context,
                'tester'
            );
            const status = response.status;
            let responseBody = "";
            try { responseBody = await response.text(); } catch (e) {}

            if (status === 400 || status === 422) {
                lastValidationStatus = status;
                continue;
            }

            const resolvedParts = testPath.split('/').filter(Boolean);
            const parameterIndex = path.split('/').filter(Boolean).findIndex(part => part === `{${paramName}}`);
            const targetId = resolvedParts[parameterIndex];
            if (status >= 300 && status < 500) {
                return findings;
            }

            if (status >= 200 && status < 300) {
            // "Ál-Sikeres" 200 OK szűrése: Ha a válaszban benne van, hogy error vagy unauthorized, az valójában védett!
            const bodyLower = responseBody.toLowerCase();
            if (bodyLower.includes('error') || bodyLower.includes('unauthorized') || bodyLower.includes('denied')) {
                    return findings;
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
            return findings;
            }
            if (status >= 500) {
            findings.push({
                owaspCategory: 'API1:2023',
                endpoint: path,
                method: method,
                severity: 'Medium',
                confidence: 'warning',
                description: `Szerver összeomlás (HTTP ${status}) egy idegen azonosító lekérésekor. Valószínűleg hiányzó objektumszintű jogosultság-ellenőrzés okozta a kivételt a kódban.`,
                payloadUsed: `Path paraméter: ${paramName}=${targetId}`
            });
                return findings;
            }
        }

        if (lastValidationStatus !== null) {
            console.warn(`[BOLA Warning] A ${path} minden kipróbált ID-val ${lastValidationStatus}-as validációs választ adott; a BOLA nem igazolható.`);
        }
        
    } catch (error) {
        console.error(`[OWASP API1 Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    return findings;
}