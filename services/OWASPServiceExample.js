/**
 * OWASP Sebezhetőség Kereső Modul Sablon
 * 
 * @param {Object} endpoint - Az aktuálisan vizsgált végpont adatai az OpenAPI specifikációból
 * @param {string} endpoint.path - Az API útvonal (pl. "/api/users/{id}")
 * @param {string} endpoint.method - HTTP metódus nagybetűvel (pl. "GET", "POST", "DELETE")
 * @param {Object} endpoint.operation - A végpont részletes OpenAPI/Swagger leírása (paraméterek, válaszok stb.)
 * 
 * @param {Object} context - A vizsgálat globális kontextusa
 * @param {string} context.targetUrl - A vizsgált szerver alap URL-je (pl. "https://api.example.com")
 * @param {Object} context.spec - A teljes, letöltött OpenAPI specifikáció objektumként (Ez a teljes szerverre vonatkozó leírás, amelyből az összes végpont kinyerhető)
 * 
 * @returns {Promise<Array<Object>>} Egy tömb, amely tartalmazza a megtalált sebezhetőségeket. 
 *                                   Ha nincs találat, KÖTELEZŐEN egy üres tömböt `[]` kell visszaadni!
 */
export async function exampleOwaspCheck(endpoint, context) {
    // 1. Üres tömb inicializálása a találatoknak
    const findings = [];

    // 2. Szükséges adatok kinyerése a teszthez
    const { path, method, operation } = endpoint;
    const { targetUrl } = context;

    // Tesztelési logika

    // 4. Mindig egy tömbbel térünk vissza!
    // Ha nincs találat, üres tömböt adj vissza különben a másik fájl hibára fut
    // Ha egy találat van akkor egy egy elemű tömböt adj vissza (ScanReport modell Vulnerabilities mezőjéhez illeszkedő objektummal)
    // Ha több találat van, akkor egy tömböt adj vissza, amely több ilyen objektumot tartalmaz
    return findings;
}