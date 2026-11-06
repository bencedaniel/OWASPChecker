import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import { startScan, getMyScans, getScanById, getAllScansAdmin, getScanByIdAdmin } from '../controllers/scanController.js';

const router = express.Router();

router.use(authenticateToken);

/**
 * @swagger
 * /api/scans:
 *   post:
 *     summary: Új biztonsági vizsgálat indítása
 *     description: Létrehoz egy pending állapotú riportot, és a háttérben elindítja a vizsgálatot.
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [targetUrl]
 *             properties:
 *               testUserCredentials:
 *                 type: object
 *                 properties:
 *                   identifier:
 *                     type: string
 *                     description: username, email, login vagy más bejelentkezési azonosító
 *                     example: user@example.test
 *                   password:
 *                     type: string
 *                     example: testpassword
 *               testAdminCredentials:
 *                 type: object
 *                 properties:
 *                   identifier:
 *                     type: string
 *                     description: username, email, login vagy más bejelentkezési azonosító
 *                     example: admin@example.test
 *                   password:
 *                     type: string
 *                     example: adminpassword
 *               targetUrl:
 *                 type: string
 *                 example: https://target.example
 *               openApiSpecUrl:
 *                 type: string
 *                 example: https://target.example/api-docs.json
 *     responses:
 *       202:
 *         description: A vizsgálat elindult.
 *       400:
 *         description: Hibás bemenet.
 *       401:
 *         description: Hiányzó vagy érvénytelen token.
 *   get:
 *     summary: A saját vizsgálatok listája
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A vizsgálatok listája (hibalista nélkül).
 */
router.post('/', startScan);
router.get('/', getMyScans);

/**
 * @swagger
 * /api/scans/{id}:
 *   get:
 *     summary: Egy vizsgálat riportja
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: A riport a talált sérülékenységekkel.
 *       404:
 *         description: A vizsgálat nem található.
 */
router.get('/:id', getScanById);



/** 
 * @swagger
 * /api/scans/admin/getAll:
 *   get:
 *     summary: Minden vizsgálat lekérdezése (admin jogosultság szükséges)
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A vizsgálatok listája.
 *       401:
 *         description: Nincs megadva hitelesítő token.
 *       403:
 *         description: Érvénytelen vagy lejárt token, vagy nincs admin jogosultság.
 *       500:
 *         description: Szerverhiba a vizsgálatok lekérésekor.
 */
router.get('/admin/getAll', getAllScansAdmin);

/**
 * @swagger
 * /api/scans/admin/{id}:
 *   get:
 *     summary: Egy vizsgálat riportja (admin jogosultság szükséges)
 *     description: Lekérdezi egy vizsgálat riportját, ha az admin jogosultsággal rendelkezik.
 *     tags: [Scans]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: A riport a talált sérülékenységekkel.
 *       404:
 *         description: A vizsgálat nem található.
 */
router.get('/admin/:id', getScanByIdAdmin); // Adminoknak, minden riport lekérdezhető


export default router;
