const { Router } = require("express");
const multer = require('multer');
const upload = multer();
const routerFirmas = Router();
const {firma_individual} = require("../controllers/firma");


routerFirmas.post('/individual', upload.single('llave'), firma_individual);

module.exports = (app) => app.use('/firma', routerFirmas);