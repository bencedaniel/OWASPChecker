import express from 'express';
import { registerUser, loginUser, getAllUsers, editUser, deleteUser } from '../controllers/authController.js';
import { authenticateToken, authenticateTokenVerifyAdmin } from '../middleware/auth.js';

const router = express.Router();

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Felhasználói regisztráció  
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody: 
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *               - email
 *             properties:
 *               username:
 *                 type: string
 *                 description: A felhasználó neve. 
 *               password:
 *                 type: string
 *                 description: A felhasználó jelszava.
 *               email:   
 *                 type: string
 *                 description: A felhasználó email címe.
 *               role:
 *                 type: string
 *                 description: A felhasználó szerepköre (opcionális, alapértelmezett "tester").
 *     responses:
 *       201:
 *         description: Sikeres regisztráció.
 *       400:
 *         description: A felhasználónév vagy email már foglalt.
 *       500:
 *         description: Szerverhiba a regisztráció során.
 */
router.post('/register', authenticateTokenVerifyAdmin, registerUser);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Felhasználói bejelentkezés
 *     tags: [Auth]

 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 description: A felhasználó neve.
 *               password:
 *                 type: string
 *                 description: A felhasználó jelszava.
 *     responses:
 *       200:
 *         description: Sikeres bejelentkezés, visszaadja a JWT tokent.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: A JWT token authentikációhoz.
 *       401:
 *         description: Hibás felhasználónév vagy jelszó.
 *       500:
 *         description: Szerverhiba a bejelentkezés során.
 */
router.post('/login', loginUser);

/** 
 * @swagger
 * /auth/users:
 *   get:
 *     summary: Összes felhasználó lekérése (admin jogosultság szükséges)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sikeres lekérés, visszaadja az összes felhasználót.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                     description: A felhasználó azonosítója.
 *                   username:
 *                     type: string
 *                     description: A felhasználó neve.
 *                   email:
 *                     type: string
 *                     description: A felhasználó email címe.
 *                   role:
 *                     type: string
 *                     description: A felhasználó szerepköre.
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *                     description: A felhasználó létrehozásának dátuma.
 *                   updatedAt:
 *                     type: string
 *                     format: date-time
 *                     description: A felhasználó utolsó frissítésének dátuma.
 *       401:
 *         description: Nincs megadva hitelesítő token.
 *       403:
 *         description: Érvénytelen vagy lejárt token, vagy nincs admin jogosultság.
 *       500:
 *         description: Szerverhiba a felhasználók lekérésekor.
 */
router.get('/users', authenticateTokenVerifyAdmin, getAllUsers);

/** 
 * @swagger
 * /auth/users/{id}:
 *   put:
 *     summary: Felhasználó adatainak módosítása (admin jogosultság szükséges)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: A felhasználó azonosítója.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: A felhasználó új neve (opcionális).
 *               email:
 *                 type: string
 *                 description: A felhasználó új email címe (opcionális).
 *               password:
 *                 type: string
 *                 description: A felhasználó új jelszava (opcionális).
 *               role:
 *                 type: string
 *                 description: A felhasználó új szerepköre (opcionális).
 *     responses:
 *       200:
 *         description: Sikeres módosítás, visszaadja a módosított felhasználót.
 *       400:
 *         description: Hibás kérés, pl. érvénytelen adatok.
 *       401:
 *         description: Nincs megadva hitelesítő token.
 *       403:
 *         description: Érvénytelen vagy lejárt token, vagy nincs admin jogosultság.
 *       404:
 *         description: A felhasználó nem található.
 *       500:
 *         description: Szerverhiba a felhasználó módosítása során.
 */
router.put('/users/:id', authenticateTokenVerifyAdmin, editUser);
/** 
 * @swagger
 * /auth/users/{id}:
 *   delete:
 *     summary: Felhasználó törlése (admin jogosultság szükséges)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: A felhasználó azonosítója.
 *     responses:
 *       200:
 *         description: Sikeres törlés.
 *       401:
 *         description: Nincs megadva hitelesítő token.
 *       403:
 *         description: Érvénytelen vagy lejárt token, vagy nincs admin jogosultság.
 *       404:
 *         description: A felhasználó nem található.
 *       500:
 *         description: Szerverhiba a felhasználó törlése során.
 */
router.delete('/users/:id', authenticateTokenVerifyAdmin, deleteUser);


export default router;