import { getAuthToken } from './reconEngine.js';

/**
 * Intelligens HTTP kliens, amely automatikusan újrahitelesít, ha a token lejárt (401).
 * 
 * @param {string} url - A célpont URL
 * @param {Object} options - A fetch opciói (method, body, stb.)
 * @param {Object} context - A globális teszt kontextus (tartalmazza a tokeneket és hitelesítő adatokat)
 * @param {string} role - Milyen szerepkörrel küldjük a kérést? ('admin' vagy 'tester')
 */
export async function smartFetch(url, options, context, role = 'tester') {
    // 1. Kiválasztjuk az aktuális tokent a kért szerepkör alapján
    let currentToken = role === 'admin' ? context.adminToken : context.testerToken;
    
    // Alapértelmezett headerek beállítása a token felhasználásával
    const headers = {
        ...options.headers,
        'Authorization': `Bearer ${currentToken}`,
        'Content-Type': 'application/json'
    };

    // 2. Első próbálkozás
    let response = await fetch(url, { ...options, headers });

    // 3. Ha 401 Unauthorized hibát kapunk, a token valószínűleg lejárt (vagy eleve rossz volt)
    if (response.status === 401) {
        console.log(`[SmartFetch] 401-es hiba a ${url} végponton. Újrahitelesítés folyamatban (${role} szerepkör)...`);
        
        // Hitelesítő adatok kiválasztása a szerepkör alapján
        const credentials = role === 'admin' ? context.report.testAdminCredentials : context.report.testUserCredentials;
        
        // Új token lekérése a célpontról
        const newToken = await getAuthToken(context.targetUrl, credentials, context.spec);

        if (newToken) {
            // Frissítjük a memóriában lévő kontextust, hogy a többi teszt is az új tokent használja
            if (role === 'admin') context.adminToken = newToken;
            else context.testerToken = newToken;

            // Frissítjük a fejlécet az új tokennel
            headers['Authorization'] = `Bearer ${newToken}`;

            // 4. Második (és egyben utolsó) próbálkozás az új tokennel
            response = await fetch(url, { ...options, headers });
        } else {
            console.error(`[SmartFetch] Az automatikus újrahitelesítés elbukott a(z) ${role} fiókkal.`);
        }
    }

    return response;
}