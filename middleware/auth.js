import jwt from 'jsonwebtoken';

export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // Elvárjuk a "Bearer <token>" formátumot
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Nincs megadva hitelesítő token.' });
    }

    // A JWT_SECRET a .env fájlból jön (pl. super_secret_key_for_testing_only)
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Érvénytelen vagy lejárt token.' });
        }
        // A dekódolt felhasználói adatokat hozzáfűzzük a kéréshez a további végpontok számára
        req.user = user;
        next();
    });
};