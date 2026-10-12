import ScanReport from '../models/ScanReport.js';
import { runScan } from '../services/scanService.js';

function isHttpUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
}

// POST /api/scans – új vizsgálat indítása
export const startScan = async (req, res) => {
    try {
        const { targetUrl, openApiSpecUrl } = req.body;

        if (!isHttpUrl(targetUrl)) {
            return res.status(400).json({ message: 'Érvényes targetUrl megadása kötelező (http/https).' });
        }

        // Ha nincs külön megadva, a Swagger szokásos helyét feltételezzük
        const specUrl = openApiSpecUrl || new URL('/api-docs.json', targetUrl).href;
        if (!isHttpUrl(specUrl)) {
            return res.status(400).json({ message: 'Érvénytelen openApiSpecUrl.' });
        }

        const report = await ScanReport.create({
            targetUrl,
            openApiSpecUrl: specUrl,
            initiatedBy: req.user.id
        });

        // Nem várjuk meg: a vizsgálat a háttérben fut, a kliens a riport ID-jával lekérdezheti az állapotot
        runScan(report._id).catch(err => console.error('Scan hiba:', err));

        res.status(202).json({
            message: 'A vizsgálat elindult.',
            scanId: report._id,
            status: report.status
        });
    } catch (error) {
        res.status(500).json({ message: 'Hiba a vizsgálat indításakor.', error: error.message });
    }
};

// GET /api/scans – a bejelentkezett felhasználó vizsgálatai (hibalista nélkül)
export const getMyScans = async (req, res) => {
    try {
        const scans = await ScanReport.find({ initiatedBy: req.user.id })
            .select('-vulnerabilities')
            .sort({ createdAt: -1 });
        res.json(scans);
    } catch (error) {
        res.status(500).json({ message: 'Hiba a vizsgálatok lekérdezésekor.', error: error.message });
    }
};

// GET /api/scans/:id – egy riport részletei
export const getScanById = async (req, res) => {
    try {
        // A tulajdonos szűrése miatt más felhasználó riportja nem kérhető le (BOLA ellen)
        const scan = await ScanReport.findOne({ _id: req.params.id, initiatedBy: req.user.id });
        if (!scan) {
            return res.status(404).json({ message: 'A vizsgálat nem található.' });
        }
        res.json(scan);
    } catch (error) {
        res.status(400).json({ message: 'Érvénytelen azonosító.' });
    }
};

export const getScanByIdAdmin = async (req, res) => {
    try {
        const scan = await ScanReport.findById(req.params.id);
        if (!scan) {
            return res.status(404).json({ message: 'A vizsgálat nem található.' });
        }
        res.json(scan);
    } catch (error) {
        res.status(400).json({ message: 'Érvénytelen azonosító.' });
    }
};

export const getAllScansAdmin = async (req, res) => {
    try {
        const scans = await ScanReport.find().sort({ createdAt: -1 });
        res.json(scans);
    } catch (error) {
        res.status(500).json({ message: 'Hiba a vizsgálatok lekérdezésekor.', error: error.message });
    }
};
