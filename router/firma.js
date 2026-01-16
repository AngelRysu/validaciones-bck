const { Router } = require("express");
const multer = require('multer');
const upload = multer();
const routerFirmas = Router();
const {firma_individual, firma_multiple} = require("../controllers/firma");


routerFirmas.post('/individual', upload.single('llave'), firma_individual);
routerFirmas.post('/multiple', upload.single('llave'), firma_multiple);

module.exports = (app) => app.use('/firma', routerFirmas);