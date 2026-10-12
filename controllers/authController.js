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