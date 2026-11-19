import { smartFetch } from '../smartFetch.js';
import { resolvePathParams } from '../pathResolver.js';

const INTEGRATION_KEYWORDS = [
    'webhook', 'callback', 'external', 'sync', 'import',
    'partner', 'integration', 'thirdparty', 'feed', 'upstream',
    'warranty', 'vendor', 'supplier', 'remote', 'fetch', 'proxy'
];

// Ezeket az útvonalakat kíméljük a mutáló (POST/PUT/PATCH) szondázástól,
// hogy a tesztfiók (pl. users/me) adatai ne sérüljenek vagy törlődjenek.
const PROTECTED_WRITE_PATH_PATTERNS = [
    /\/users\/me\b/i,
    /\/me\b/i,
    /\/profile\b/i,
    /\/account\b/i
];

const URL_FIELD_NAMES = [
    'url', 'uri', 'endpoint', 'targeturl', 'callbackurl',
    'webhookurl', 'feedurl', 'externalurl', 'sourceurl', 'remoteurl'
];

const UNSANITIZED_PATTERNS = [
    {
        name: 'Potenciális XSS / HTML injekció (<script>, <iframe>, javascript:, event handler)',
        regex: /<(script|iframe|object|embed)[\s>]|javascript:|on(error|load|click|mouseover|focus|blur|submit)\s*=/i
    },
    {
        name: 'Potenciális NoSQL operátor ($ne / $gt / $lt / $or / $where / $regex)',
        regex: /\$+(ne|gt|gte|lt|lte|or|and|nor|where|regex|exists|elemMatch|type)\b/i
    },
    {
        name: 'Potenciális kódfuttatási / dinamikus kiértékelési minta (eval / Function)',
        regex: /\b(eval|new\s+Function)\s*\(/i
    }
];

const MAX_CANDIDATE_PATHS = 8;

/**
 * OWASP API10:2023 – Unsafe Consumption of APIs
 */
export async function checkApi10UnsafeConsumption(endpoint, context) {
    const findings = [];
    const { path, method, operation } = endpoint;
    const { targetUrl, harvestedIds } = context;

    const upperMethod = method.toUpperCase();
    if (upperMethod === 'DELETE' && context.allowDestructive !== true) {
        return findings;
    }
    const lowerPath = path.toLowerCase();
    const summaryOrDesc = `${operation?.summary || ''} ${operation?.description || ''}`.toLowerCase();

    const isIntegrationEndpoint =
        INTEGRATION_KEYWORDS.some(keyword => lowerPath.includes(keyword)) ||
        INTEGRATION_KEYWORDS.some(keyword => summaryOrDesc.includes(keyword));

    const isProtectedWriteEndpoint =
        ['POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod) &&
        PROTECTED_WRITE_PATH_PATTERNS.some(regex => regex.test(path));

    const acceptsUrlField = endpointAcceptsUrlField(operation);
    const candidatePaths = buildCandidatePaths(path, harvestedIds);

    if (candidatePaths.length === 0) {
        return findings;
    }

    const baseUrl = targetUrl.replace(/\/$/, '');

    try {
        // 1. Integrációs jellegű végpontok vizsgálata
        if (isIntegrationEndpoint) {
            let gotSuccessfulResponse = false;

            for (const resolvedPath of candidatePaths) {
                const fullUrl = `${baseUrl}${resolvedPath}`;
                const requestOptions = {
                    method: upperMethod,
                    headers: { 'Content-Type': 'application/json' }
                };

                // Csak akkor küldünk body-t író metóduson, ha nem védett fiók/profil végpont
                if (['POST', 'PUT', 'PATCH'].includes(upperMethod) && !isProtectedWriteEndpoint) {
                    requestOptions.body = JSON.stringify({
                        source: 'api10_probe',
                        url: 'https://untrusted-source.example.invalid/data',
                        payload: 'probe_value'
                    });
                }
                console.log(`[API10 Probe] ${upperMethod} ${fullUrl}`);
                const response = await smartFetch(fullUrl, requestOptions, context, 'tester');
                const rawBody = await response.text().catch(() => '');

                if (response.status >= 200 && response.status < 300) {
                    gotSuccessfulResponse = true;
                    const matchedPatterns = findUnsanitizedPatterns(rawBody);

                    if (matchedPatterns.length > 0) {
                        findings.push({
                            owaspCategory: 'API10:2023',
                            endpoint: path,
                            method: upperMethod,
                            severity: 'High',
                            confidence: 'danger',
                            description: `Unsafe Consumption of APIs: A(z) "${path}" végpont válaszában tisztítatlan, külső/partner forrásból származó minta jelent meg (${matchedPatterns.join(', ')}).`,
                            payloadUsed: `${upperMethod} ${resolvedPath}`
                        });
                        return findings;
                    }
                }
            }

            if (gotSuccessfulResponse) {
                findings.push({
                    owaspCategory: 'API10:2023',
                    endpoint: path,
                    method: upperMethod,
                    severity: 'Medium',
                    confidence: 'warning',
                    description: `Unsafe Consumption of APIs: Integrációs/külső adatforráshoz kapcsolódó végpont ("${path}") sikeres (2xx) választ adott; ellenőrizni kell a külső válaszok sémavalidálását, szanálását és timeout/méretkorlátait.`,
                    payloadUsed: `${upperMethod} ${candidatePaths[0]}`
                });
            }
        } else {
            // 2. Általános végpontok választörzs-ellenőrzése (csak biztonságos/nem-destruktív módon)
            if (!['DELETE'].includes(upperMethod) && !isProtectedWriteEndpoint) {
                const primaryPath = candidatePaths[0];
                const fullUrl = `${baseUrl}${primaryPath}`;

                const generalResponse = await smartFetch(fullUrl, { method: upperMethod }, context, 'tester');
                const generalBody = await generalResponse.text().catch(() => '');

                if (generalResponse.status >= 200 && generalResponse.status < 300) {
                    const matchedPatterns = findUnsanitizedPatterns(generalBody);

                    if (matchedPatterns.length > 0) {
                        findings.push({
                            owaspCategory: 'API10:2023',
                            endpoint: path,
                            method: upperMethod,
                            severity: 'High',
                            confidence: 'danger',
                            description: `Unsafe Consumption of APIs: A(z) "${path}" végpont válaszában tisztítatlan minta jelent meg (${matchedPatterns.join(', ')}).`,
                            payloadUsed: `${upperMethod} ${primaryPath}`
                        });
                    }
                }
            }
        }

        // 3. Külső URL-t fogadó mezők ellenőrzése (védett fiók/profil végpontok kihagyásával)
        if (acceptsUrlField && ['POST', 'PUT', 'PATCH'].includes(upperMethod) && !isProtectedWriteEndpoint) {
            const targetPath = candidatePaths[0];
            const urlProbeRes = await smartFetch(
                `${baseUrl}${targetPath}`,
                {
                    method: upperMethod,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: 'https://untrusted-external-api.example.invalid/feed',
                        callbackUrl: 'https://untrusted-external-api.example.invalid/callback'
                    })
                },
                context,
                'tester'
            );

            const urlProbeBody = await urlProbeRes.text().catch(() => '');
            if (urlProbeRes.status >= 200 && urlProbeRes.status < 300) {
                const urlMatched = findUnsanitizedPatterns(urlProbeBody);
                const alreadyHasDanger = findings.some(f => f.confidence === 'danger');

                if (!alreadyHasDanger) {
                    findings.push({
                        owaspCategory: 'API10:2023',
                        endpoint: path,
                        method: upperMethod,
                        severity: urlMatched.length > 0 ? 'High' : 'Low',
                        confidence: urlMatched.length > 0 ? 'danger' : 'warning',
                        description: urlMatched.length > 0
                            ? `Unsafe Consumption of APIs: A(z) "${path}" végpont külső URL-lel hívva tisztítatlan tartalmat adott vissza (${urlMatched.join(', ')}).`
                            : `Unsafe Consumption of APIs: A(z) "${path}" végpont külső URL-t tartalmazó bemenetet ${urlProbeRes.status} státusszal elfogadott; érdemes ellenőrizni a külső forrás validálását.`,
                        payloadUsed: `${upperMethod} ${targetPath} (külső URL mező)`
                    });
                }
            }
        }
    } catch (error) {
        console.error(`[OWASP API10 Hiba] A(z) ${path} végpont tesztelése közben:`, error.message);
    }

    return findings;
}

function buildCandidatePaths(path, harvestedIds) {
    const candidates = new Set();

    const primaryResolved = resolvePathParams(path, harvestedIds);
    if (primaryResolved && !primaryResolved.includes('{')) {
        candidates.add(primaryResolved);
    }

    if (path.includes('{') && harvestedIds && typeof harvestedIds === 'object') {
        const values = Array.isArray(harvestedIds)
            ? harvestedIds
            : Object.values(harvestedIds).flat();

        for (const val of values) {
            if (candidates.size >= MAX_CANDIDATE_PATHS) break;
            if (typeof val === 'string' || typeof val === 'number') {
                const replaced = path.replace(/\{[^}]+\}/g, String(val));
                if (!replaced.includes('{')) {
                    candidates.add(replaced);
                }
            }
        }
    }

    return Array.from(candidates);
}

function findUnsanitizedPatterns(bodyText) {
    if (typeof bodyText !== 'string' || !bodyText) {
        return [];
    }
    return UNSANITIZED_PATTERNS
        .filter(pattern => pattern.regex.test(bodyText))
        .map(pattern => pattern.name);
}

function endpointAcceptsUrlField(operation) {
    const schema = operation?.requestBody?.content?.['application/json']?.schema;
    if (!schema) return false;

    const serialized = JSON.stringify(schema).toLowerCase();
    return URL_FIELD_NAMES.some(field => serialized.includes(`"${field}"`));
}