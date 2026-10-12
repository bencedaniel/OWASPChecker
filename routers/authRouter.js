
import express from 'express';
import { registerUser, loginUser } from '../controllers/authController.js';
import { authenticateToken, authenticateTokenVerifyAdmin } from '../middleware/auth.js';

const router = express.Router();

/**
 * @swagger
    * /auth/register:
    *  post:
    *   summary: Felhasználói regisztráció  
    *  tags: [Auth]
    *  requestBody: 
    *    required: true
    *   content:
    *    application/json:
    *     schema:
    *    type: object
    *   properties:
    *   username:
    *   type: string
    *  description: A felhasználó neve. 
    *  password:
    *   type: string
    * description: A felhasználó jelszava.
    *  email:   
    *   type: string
    * description: A felhasználó email címe.
    *  role:
    *   type: string
    * description: A felhasználó szerepköre (opcionális, alapértelmezett: 'tester').
    *  required:
    *   - username
    *   - password
    *   - email
    *  responses:
    *   201:
    *    description: Sikeres regisztráció.
    *   400:
    *    description: A felhasználónév vagy email már foglalt.
    *   500:
    *    description: Szerverhiba a regisztráció során.
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
 *             properties:
 *               username:
 *                 type: string
 *                 description: A felhasználó neve.
 *               password:
 *                 type: string
 *                 description: A felhasználó jelszava.
 *             required:
 *               - username
 *               - password
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





export default router;