// Környezeti változók betöltése ES modulként
import 'dotenv/config'; 

// Alapvető csomagok importálása
import express from 'express';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import connectDB from './db/db.js';
import morgan from 'morgan';



const app = express();
app.use(express.json());
app.use(morgan('dev')); // HTTP kérések logolása a konzolra
// Swagger-jsdoc konfiguráció
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'OwASP API Security Lab',
      version: '1.0.0',
      description: 'OwASP API Security Lab - Teszteléshez és oktatáshoz',
    },
    servers: [
      {
        url: `http://localhost:${process.env.PORT || 3000}`,
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  // Mivel a kódodban a 'routers' mappát hivatkoztad, itt is frissíteni kell az elérési utat
  apis: ['./src/routers/*.js', './src/controllers/*.js'], 
};

// OpenAPI dokumentum generálása és Swagger UI kiszolgálása
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ÚJ SOR: Nyers OpenAPI JSON publikálása a biztonsági scanner számára
app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
});

// Routerek (végpontok) bekötése

app.get('/health', (req, res) => {
    res.json({ status: "OwASP API Security Lab fut!" });
});

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;

// Adatbázis csatlakozás és a szerver indítása
const startServer = async () => {
    try {
        // Megvárjuk, amíg az adatbázis kapcsolat felépül
        await connectDB(MONGODB_URI);
        
        // Csak sikeres DB kapcsolat után indítjuk az Express szervert
        app.listen(PORT, () => {
            console.log(`A szerver elindult a ${PORT}-es porton.`);
            console.log(`API Dokumentáció: http://localhost:${PORT}/api-docs`);
        });
    } catch (error) {
        console.error('Kritikus hiba induláskor:', error);
        process.exit(1);
    }
};

// Inicializálás
startServer();