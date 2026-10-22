import ScanReport from '../models/ScanReport.js';
import { getAuthToken, harvestResourceIds } from './reconEngine.js';
import { checkApi1Bola } from './owaspChecks/api1_bola.js';
import { brokenAuthCheck } from './owaspChecks/brokenAuth.js'; // Vagy ahogy elneveztétek

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete'];


const checks = [
    checkApi1Bola,
    brokenAuthCheck
];

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

        // --- 1. AUTENTIKÁCIÓ (Bejelentkezés dinamikusan a tesztfiókokkal) ---
        const adminToken = await getAuthToken(report.targetUrl, report.testAdminCredentials, spec);
        const testerToken = await getAuthToken(report.targetUrl, report.testUserCredentials, spec);

        // --- 2. RECON (Adatgyűjtés) ---
        let harvestedIds = {};
        if (adminToken) {
            harvestedIds = await harvestResourceIds(report.targetUrl, spec, adminToken);
            console.log("[Recon] Felderítés kész:", harvestedIds);
        } else {
            console.warn("[Recon] Nincs Admin token, az automatikus adatgyűjtés kimaradt.");
        }

        // --- 3. TESZTELÉS (Context összeállítása az összes tesztmodulnak) ---
        const context = { 
            targetUrl: report.targetUrl, 
            spec,
            report,
            adminToken,      
            testerToken,     
            harvestedIds
        };
        
        const findings = [];
        for (const endpoint of endpoints) {
            for (const check of checks) {
                findings.push(...await check(endpoint, context));
            }
        }

        // --- 4. KIÉRTÉKELÉS ÉS MENTÉS ---
        report.vulnerabilities = findings;
        report.status = 'completed';
        
        // JAVÍTÁS: A JavaScript tömböknek nincs count() metódusa, helyette:
        const dangerCount = findings.filter(f => f.confidence === 'danger').length;
        const warningCount = findings.filter(f => f.confidence === 'warning').length;

        report.summary = `A vizsgálat befejeződött. ${findings.length} sebezhetőség található. ${dangerCount} kritikus, ${warningCount} figyelmeztetés.`;
        
    } catch (err) {
        report.status = 'failed';
        report.errorMessage = err.message;
        console.error("[Szkenner Hiba]:", err);
    } finally {
        report.endTime = new Date();
        await report.save();
    }
}