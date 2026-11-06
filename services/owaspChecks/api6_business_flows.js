import { smartFetch } from '../smartFetch.js';
import { resolvePathParams } from '../pathResolver.js';

/**
 * OWASP API6:2023 – Unrestricted Access to Sensitive Business Flows
 * Azt vizsgálja, hogy egy üzletileg érzékeny művelet (regisztráció, kuponbeváltás,
 * vásárlás stb.) ismételhető-e korlátozás nélkül, visszaélésre adva lehetőséget.
 */
export async function checkApi6BusinessFlows(endpoint, context) {
    const findings = [];
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    const upperMethod = method.toUpperCase();
    if (!['POST', 'PUT', 'PATCH'].includes(upperMethod)) {
        return findings;
    }

    const lowerPath = path.toLowerCase();
    const sensitiveFlowKeywords = [
        'coupon', 'voucher', 'redeem', 'discount', 'promo',
        'register', 'signup', 'sign-up', 'invite', 'referral',
        'order', 'purchase', 'checkout', 'payment', 'booking', 'reserve',
        'vote', 'like', 'review', 'comment', 'follow'
    ];
    if (!sensitiveFlowKeywords.some(keyword => lowerPath.includes(keyword))) {
        return findings;
    }

// --- 4. CÉLPONT ADATOK ELŐKÉSZÍTÉSE ---
    const resolvedPath = resolvePathParams(path, harvestedIds);
    if (!resolvedPath) return findings;

    const fullUrl = `${targetUrl.replace(/\/$/, '')}${resolvedPath}`;
    const schema = operation.requestBody?.content?.['application/json']?.schema;
    const basePayload = generateMockPayloadFromSchema(schema);

    try {
        const repeatCount = 5;
        const successStatuses = [];

        for (let i = 0; i < repeatCount; i++) {
            const payload = {
                ...basePayload,
                ...createUniqueFlowValues(basePayload, i)
            };
            const requestOptions = {
                method: upperMethod,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            };

            const response = await smartFetch(fullUrl, requestOptions, context, 'tester');
            successStatuses.push(response.status);
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        const successCount = successStatuses.filter(status => status >= 200 && status < 300).length;
        const blockedCount = successStatuses.filter(status => status === 429 || status === 409 || status === 403).length;

        if (successCount === repeatCount && blockedCount === 0) {
            findings.push({
                owaspCategory: 'API6:2023',
                endpoint: path,
                method: method,
                severity: 'Medium',
                confidence: 'warning',
                description: `Unrestricted Access to Sensitive Business Flows: Az üzletileg érzékeny végpont ${repeatCount}/${repeatCount} ismételt hívást is korlátozás nélkül kiszolgált (nincs 429/409/403 visszautasítás). Automatizált visszaélés (pl. kuponhalmozás, spam regisztráció) lehetséges.`,
                payloadUsed: `${repeatCount}x ${method} ${resolvedPath} | Body: ${JSON.stringify(basePayload)}`
            });
        }

        function createUniqueFlowValues(payload, attempt) {
            const suffix = `${Date.now()}_${attempt}`;
            const values = {};
            for (const key of Object.keys(payload)) {
                const normalizedKey = key.toLowerCase();
                if (normalizedKey.includes('email')) values[key] = `flow_test_${suffix}@scanner.invalid`;
                if (normalizedKey.includes('username') || normalizedKey === 'user') {
                    values[key] = `flow_test_${suffix}`;
                }
            }
            return values;
        }

    } catch (error) {
        console.error(`[OWASP API6 Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    return findings;
}

function generateMockPayloadFromSchema(schema) {
    if (!schema || !schema.properties) return {};
    const mock = {};
    for (const [key, prop] of Object.entries(schema.properties)) {
        if (prop.type === 'string') mock[key] = "flow_test_value";
        else if (prop.type === 'number' || prop.type === 'integer') mock[key] = 1;
        else if (prop.type === 'boolean') mock[key] = true;
        else if (prop.type === 'array') mock[key] = [];
        else mock[key] = "test";
    }
    return mock;
}
