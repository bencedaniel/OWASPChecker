// Mongoose (MongoDB ODM) importálása
import mongoose from 'mongoose';
// Node.js path modul importálása
// fileURLToPath segédfüggvény importálása (ESM modulokhoz)
// Környezeti változók betöltése
// Logger és naplózó függvények importálása
// MongoDB URI importálása a környezeti konfigurációból

export default async function connectDB(MONGODB_URI) {
    try {
        // Adatbázis kapcsolódás indítása
        await mongoose.connect(MONGODB_URI);
        console.log('DB_CONNECT', 'Successfully connected to MongoDB', '');

        // Kapcsolat lezárása (graceful shutdown) kilépéskor (Ctrl+C)
        process.on('SIGINT', async () => {
            try {
                await mongoose.disconnect();
                console.log('DB_DISCONNECT', 'Connection to MongoDB closed.', '');
                process.exit(0);
            } catch (err) {
                console.error('DB_DISCONNECT', 'Failed to disconnect from MongoDB', err.toString());
                process.exit(1);
            }
        });
    } catch (err) {
        // Hibakezelés: sikertelen kapcsolódás esetén logol és kilép
        console.error('DB_CONNECTION', 'Connection error', err.toString());
        process.exit(1);
    }
}

// Adatbázis kapcsolódás exportálása
