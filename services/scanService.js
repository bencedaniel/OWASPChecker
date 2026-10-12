import ScanReport from '../models/ScanReport.js';

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];

// Ide kerülnek majd a tesztmodulok (auth, BOLA, inputvalidáció, rate limit...).
// Mindegyik: async (endpoint, context) => [vulnerability, ...]
const checks = [];

async function loadSpec(specUrl) {
    const response = await fetch(specUrl);
    if (!response.ok) {
        throw new Error(`Az OpenAPI-specifikáció nem tölthető le (HTTP ${response.status})`);
    }
    return response.json();
}

function extractEndpoints(spec) {
    const endpoints = [];
    for (const [path, operations] of Object.entries(spec.paths ?? {})) {
        for (const [method, operation] of Object.entries(operations)) {
            if (HTTP_METHODS.includes(method)) {
                endpoints.push({ path, method: method.toUpperCase(), operation });
            }
        }
    }
    return endpoints;
}

export async function runScan(reportId) {
    const report = await ScanReport.findById(reportId);
    if (!report) return;

    try {
        report.status = 'running';
        await report.save();

        const spec = await loadSpec(report.openApiSpecUrl);
        const endpoints = extractEndpoints(spec);
        report.totalEndpointsScanned = endpoints.length;

        const context = { targetUrl: report.targetUrl, spec };
        const findings = [];
        for (const endpoint of endpoints) {
            for (const check of checks) {
                findings.push(...await check(endpoint, context));
            }
        }

        report.vulnerabilities = findings;
        report.status = 'completed';
    } catch (err) {
        report.status = 'failed';
        report.errorMessage = err.message;
    } finally {
        report.endTime = new Date();
        await report.save();
    }
}
