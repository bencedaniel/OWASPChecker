import { smartFetch } from '../apiClient.js';

/**
 * OWASP API7:2023 – Server Side Request Forgery (SSRF)
 * Azt vizsgálja, hogy egy URL-t/hivatkozást váró mező elfogadja és ténylegesen
 * lekéri-e szerver oldalon a megadott belső/privát célcímet.
 */
export async function checkApi7Ssrf(endpoint, context) {
    const findings = [];
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    const upperMethod = method.toUpperCase();
    if (!['POST', 'PUT', 'PATCH'].includes(upperMethod)) {
        return findings;
    }

    const schema = operation.requestBody?.content?.['application/json']?.schema;
    const urlFieldName = findUrlLikeField(schema);
    if (!urlFieldName) {
        return findings;
    }

    const resolvedPath = path.replace(/\{([^}]+)\}/g, (_, paramName) => {
        const pathParts = path.split('/').filter(Boolean);
        const paramIndex = pathParts.findIndex(part => part.includes('{'));
        let resourceCategory = paramIndex > 0 ? pathParts[paramIndex - 1] : '';
        const validIds = harvestedIds[resourceCategory] || [];
        return validIds.length > 0 ? validIds[0] : '1';
    });

    const fullUrl = `${targetUrl.replace(/\/$/, '')}${resolvedPath}`;
    const basePayload = generateMockPayloadFromSchema(schema);

    const ssrfTestTargets = [
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1:80/',
        'http://localhost/',
        'file:///etc/passwd'
    ];

    try {
        for (const testTarget of ssrfTestTargets) {
            const payload = { ...basePayload, [urlFieldName]: testTarget };

            const requestOptions = {
                method: upperMethod,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            };

            const startTime = Date.now();
            const response = await smartFetch(fullUrl, requestOptions, context, 'tester');
            const elapsedMs = Date.now() - startTime;
            const status = response.status;

            let responseBody = "";
            try { responseBody = await response.text(); } catch (e) {}

            if (status === 400 || status === 422) {
                continue;
            }

            const bodyLower = responseBody.toLowerCase();
            const leaksInternalContent =
                bodyLower.includes('root:') ||
                bodyLower.includes('ami-id') ||
                bodyLower.includes('instance-id') ||
                bodyLower.includes('meta-data');

            if (leaksInternalContent) {
                findings.push({
                    owaspCategory: 'API7:2023',
                    endpoint: path,
                    method: method,
                    severity: 'Critical',
                    confidence: 'danger',
                    description: `SSRF sebezhetőség igazolva: a(z) "${urlFieldName}" mezőbe adott belső célcím (${testTarget}) lekérésekor a válasz belső/metaadat-jellegű tartalmat tartalmazott.`,
                    payloadUsed: `${method} ${resolvedPath} | ${urlFieldName}=${testTarget}`
                });
                continue;
            }

            if (status >= 200 && status < 300 &&
                !bodyLower.includes('error') && !bodyLower.includes('invalid') && !bodyLower.includes('denied')) {
                findings.push({
                    owaspCategory: 'API7:2023',
                    endpoint: path,
                    method: method,
                    severity: 'Medium',
                    confidence: 'warning',
                    description: `Potenciális SSRF: a(z) "${urlFieldName}" mező elfogadta a belső/privát célcímet (${testTarget}) HTTP ${status} válasszal, validációs elutasítás nélkül. Kézi ellenőrzés javasolt.`,
                    payloadUsed: `${method} ${resolvedPath} | ${urlFieldName}=${testTarget}`
                });
            }

            if (elapsedMs > 5000 && status >= 500) {
                findings.push({
                    owaspCategory: 'API7:2023',
                    endpoint: path,
                    method: method,
                    severity: 'Low',
                    confidence: 'warning',
                    description: `Gyanús válaszidő-anomália (${elapsedMs}ms) és szerverhiba (HTTP ${status}) a(z) "${urlFieldName}" mezőbe adott belső célcím (${testTarget}) esetén.`,
                    payloadUsed: `${method} ${resolvedPath} | ${urlFieldName}=${testTarget}`
                });
            }
        }

    } catch (error) {
        console.error(`[OWASP API7 SSRF Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    return findings;
}

function findUrlLikeField(schema) {
    if (!schema || !schema.properties) return null;
    const urlNameHints = ['url', 'uri', 'link', 'webhook', 'callback', 'avatar', 'image', 'thumbnail', 'redirect', 'endpoint', 'target'];

    for (const [key, prop] of Object.entries(schema.properties)) {
        const lowerKey = key.toLowerCase();
        const isUrlFormat = prop.format === 'uri' || prop.format === 'url';
        const isUrlNamed = urlNameHints.some(hint => lowerKey.includes(hint));
        if (prop.type === 'string' && (isUrlFormat || isUrlNamed)) {
            return key;
        }
    }
    return null;
}

function generateMockPayloadFromSchema(schema) {
    if (!schema || !schema.properties) return {};
    const mock = {};
    for (const [key, prop] of Object.entries(schema.properties)) {
        if (prop.type === 'string') mock[key] = "ssrf_test_value";
        else if (prop.type === 'number' || prop.type === 'integer') mock[key] = 1;
        else if (prop.type === 'boolean') mock[key] = true;
        else if (prop.type === 'array') mock[key] = [];
        else mock[key] = "test";
    }
    return mock;
}
