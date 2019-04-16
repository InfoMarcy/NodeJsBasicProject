//library for working with  logs
//working with log files
const log4js = require('log4js');
const logger = log4js.getLogger("error middleware");
const validarJson = require("../middleware/validarJson");

module.exports = function(error, req, res, next){
  
    logger.info({ mensaje: "Incidencia al conectarse con el servidor", error:  error.message});


    //Log the exception
    res.status(500).send({
        "codigo": "500.BancaDigital-Usuarios-Gitlab.CI-120",
        "mensaje": "Error al realizar la operación",
        "folio": validarJson.generarFolio(req.connection.remoteAddress),
        "info": "https://baz-developer.bancoazteca.com.mx/errors#500",
      });
};