import jwt from 'jsonwebtoken';
import User from '../models/User.js';



export const loginUser = async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Hibás felhasználónév vagy jelszó.' });
        }

        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Hibás felhasználónév vagy jelszó.' });
        }

        // JWT token generálása
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token });
    } catch (error) {
        console.error('Bejelentkezési hiba:', error);
        res.status(500).json({ error: 'Szerverhiba a bejelentkezés során.' });
    }
};
export const registerUser = async (req, res) => {
    const { username, email, password, role } = req.body;

    try {
        // Ellenőrizzük, hogy a felhasználónév vagy email már létezik-e
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'A felhasználónév vagy email már foglalt.' });
        }

        // Új felhasználó létrehozása
        const newUser = new User({ username, email, password, role });
        await newUser.save();

        res.status(201).json({ message: 'Felhasználó sikeresen regisztrálva.' });
    } catch (error) {
        console.error('Regisztrációs hiba:', error);
        res.status(500).json({ error: 'Szerverhiba a regisztráció során.' });
    }
};

export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find({}, '-password'); // A jelszó mezőt kizárjuk a lekérdezésből
        res.json(users);
    } catch (error) {
        console.error('Hiba a felhasználók lekérésekor:', error);
        res.status(500).json({ error: 'Szerverhiba a felhasználók lekérésekor.' });
    }
};

export const editUser = async (req, res) => {
    const userId = req.params.id;
    const { username, email, password, role } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'Felhasználó nem található.' });
        }

        // Frissítjük a felhasználó adatait
        if (username) user.username = username;
        if (email) user.email = email;
        if (password) user.password = password; // A jelszó automatikusan hashelődik a pre-save hookban
        if (role) user.role = role;

        await user.save();
        res.json({ message: 'Felhasználó sikeresen frissítve.' });
    } catch (error) {
        console.error('Hiba a felhasználó szerkesztésekor:', error);
        res.status(500).json({ error: 'Szerverhiba a felhasználó szerkesztésekor.' });
    }
};

export const deleteUser = async (req, res) => {
    const { userId } = req.params;
    const authenticatedUserId = req.user.id;

    // Ellenőrizzük, hogy a felhasználó nem próbálja-e törölni saját magát
    if (userId === authenticatedUserId) {
        return res.status(400).json({ error: 'Nem törölheted saját magad.' });
    }
    try {
        const user = await User.findByIdAndDelete(userId);
        if (!user) {
            return res.status(404).json({ error: 'Felhasználó nem található.' });
        }

        res.json({ message: 'Felhasználó sikeresen törölve.' });
    } catch (error) {
        console.error('Hiba a felhasználó törlésekor:', error);
        res.status(500).json({ error: 'Szerverhiba a felhasználó törlésekor.' });
    }
};