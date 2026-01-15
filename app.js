const express = require("express");
const dotenv = require("dotenv");
const http = require("http");
const https = require("https");
const fs = require("fs");
const cors = require('cors');

const routerFirmas = require("./router/firma");

dotenv.config();

const app = express();
app.use(express.json());

const FRONTEND_ORIGIN = process.env.NODE_ENV === 'PRODUCCION' 
    ? process.env.FRONTEND_URL_PROD 
    : ['http://localhost:5173', 'http://127.0.0.1:5173'];

const corsOptions = {
    origin: FRONTEND_ORIGIN, 
    methods: ['GET', 'POST', 'OPTIONS', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'api_key', 'X-API-KEY'], 
    credentials: true,
    optionsSuccessStatus: 204 
};
app.use(cors(corsOptions)); 

routerFirmas(app);

let server;
if (process.env.NODE_ENV === 'PRODUCCION') {
    try {
        const privateKey  = fs.readFileSync(process.env.PRIVKEY, 'utf8');
        const ca = fs.readFileSync(process.env.CA, 'utf8');
        const certificate = fs.readFileSync(process.env.CERT, 'utf8');
    
        const credentials = { key: privateKey, ca: ca, cert: certificate };        
        server = https.createServer(credentials, app);
        server.listen(process.env.PORT, () => {
            console.log('Servidor HTTPS (WSS) corriendo en puerto:', process.env.PORT);
        });
    } catch (error) {
        console.error("Error cargando certificados SSL:", error);
    }

} else {

    server = http.createServer(app);
    server.listen(process.env.PORT, () => {
        console.log('Servidor HTTP (WS) desarrollo corriendo en puerto:', process.env.PORT);
    });
}

module.exports = app;