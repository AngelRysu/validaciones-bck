const { Router } = require("express");
const { getValidacion, deleteValidacion } = require("../controllers/validacion");

const routerValidacion = Router();

routerValidacion.get('/:ui', getValidacion);
routerValidacion.delete('/:ui/cancelar', deleteValidacion);

module.exports = (app) => app.use('/validacion',routerValidacion);