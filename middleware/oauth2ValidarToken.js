const config = require("config");
const dateFormat = require("dateformat");
const now = new Date();
//working with log files
const log4js = require("log4js");
const logger = log4js.getLogger("Oauth2Token");
const validarJson = require("../middleware/validarJson");
const numIntentosIpService = require('../services/numIntentosIPService');
const bloqueoIPService = require('../services/bloqueoIPService');
const validaciones = require('../middleware/validaciones');
const ipService = require('./ipWhiteListService');
const cifradojson = require('../encriptado/cifradoJson');

module.exports = async function(req, res, next){

  logger.info("La llamada proviene de la Ip => ", { ip: req.connection.remoteAddress});
  logger.info("La llamada proviene de la Ip Encriptada => ", { ip_encriptada: cifradojson.Encrypt_File(req.connection.remoteAddress).toString() });
 

if(!req.body){
  console.log("No body sent");
  return res.status(400).send(cifradojson.Encrypt_File( JSON.stringify({
    codigo: "400.BancaDigital-Usuarios-Gitlab.CI-104",
    mensaje: "Los Datos de entrada no cumplen con el formato esperado",
    folio: validarJson.generarFolio(req.connection.remoteAddress),
    info:
      "https://baz-developer.bancoazteca.com.mx/errors#400.BancaDigital-Usuarios-Gitlab.CI-104",
      cgSalida: "CI-104",
      descSalida: "El Cuerpo del requerimiento es requerido"
  })));
};


  let wsDatos =  JSON.parse(cifradojson.Decrypt_File(req.body));
  let validarEmpleadoRecibido = {};
 


  if(wsDatos != null || wsDatos != 'undefined'){

    validarEmpleadoRecibido = {
      numEmpleado:   wsDatos.numEmpleado
    };

  }


  logger.info("wsDatos numEmpleado => ", wsDatos.numEmpleado);
  logger.info("wsDatos authoprization => ", wsDatos.authorization);

  if(!wsDatos.authorization){
    console.log("No Authorization Code");
    return res.status(403).send(cifradojson.Encrypt_File( JSON.stringify({
      codigo: "403.BancaDigital-Usuarios-Gitlab.CI-116",
      mensaje: "Error al realizar la operación (No Token)",
      folio: validarJson.generarFolio(req.connection.remoteAddress),
      info:
        "https://baz-developer.bancoazteca.com.mx/errors#403.BancaDigital-Usuarios-Gitlab.CI-116",
        cgSalida: "CI-116",
        descSalida: "No estas autorizado para consumir este recurso"
    })));
  };


    // validate the body of the request
    const { error } = validaciones.validateNumEmpleado(validarEmpleadoRecibido);
    if (error){
      logger.info("error => ", error);
      return res.status(400).send(cifradojson.Encrypt_File( JSON.stringify({
        codigo: "400.BancaDigital-Usuarios-Gitlab.CI-104",
        mensaje: "Los Datos de entrada no cumplen con el formato esperado",
        folio: validarJson.generarFolio(req.connection.remoteAddress),
        info:
          "https://baz-developer.bancoazteca.com.mx/errors#400.BancaDigital-Usuarios-Gitlab.CI-104",
          cgSalida: "CI-104",
          descSalida: error.details[0].message
      })));
    }


    const { ipError } = validaciones.validateIp(req.connection.remoteAddress);
    if (ipError) {
  
      logger.info("ipError => ", ipError);
  
      return res.status(400).send(cifradojson.Encrypt_File( JSON.stringify({
        codigo: "400.BancaDigital-Usuarios-Gitlab.CI-104",
        mensaje: "Los Datos de entrada no cumplen con el formato esperado",
        folio: validarJson.generarFolio(req.connection.remoteAddress),
        info:
          "https://baz-developer.bancoazteca.com.mx/errors#400.BancaDigital-Usuarios-Gitlab.CI-104",
          cgSalida: "CI-104",
          descSalida: ipError.details[0].message
      })));
    };
   



      // get the token from the header
      let authorizationCode = wsDatos.authorization;
  logger.info("authorizationCode => ", authorizationCode);

  if(!authorizationCode){
    logger.info("No authorizationCode => ", authorizationCode);
    return res.status(403).send(cifradojson.Encrypt_File( JSON.stringify({
      codigo: "403.BancaDigital-Usuarios-Gitlab.CI-116",
      mensaje: "Error al realizar la operación (No Token)",
      folio: validarJson.generarFolio(req.connection.remoteAddress),
      info:
        "https://baz-developer.bancoazteca.com.mx/errors#403.BancaDigital-Usuarios-Gitlab.CI-116",
        cgSalida: "CI-116",
        descSalida: "No estas autorizado para consumir este recurso"
    })));
  };


  //=============================== Validar  IP en White List==========================================//
        let ipWhiteList = ipService.getByIp(cifradojson.Encrypt_File(req.connection.remoteAddress).toString());
        logger.info("ipWhiteList => ", ipWhiteList);
          if (ipWhiteList == 0 ){
                return res.status(403).send(cifradojson.Encrypt_File( JSON.stringify({
                  codigo: "403.BancaDigital-Usuarios-Gitlab.CI-116",
                  mensaje: "Error al realizar la operación",
                  folio: validarJson.generarFolio(req.connection.remoteAddress),
                  info:
                    "https://baz-developer.bancoazteca.com.mx/errors#403.BancaDigital-Usuarios-Gitlab.CI-116",
                    cgSalida: "CI-116",
                    descSalida: "No estas autorizado para consumir este recurso"
                })));
    
        };

  //=============================== Validar Bloqueo por IP ==========================================//

    // get usuario por Ip
    let IpBloqueada = bloqueoIPService.getByIp(
      cifradojson.Encrypt_File(req.connection.remoteAddress).toString()
    );
    logger.info("IpBloqueada => ", IpBloqueada);

    if (IpBloqueada !== 0) {

      // Desbloquear Ip
      if (validaciones.validateFechaBloqueo(IpBloqueada.fecha_bloqueo) && IpBloqueada !== 0) {
        // desbloquear Usuario por Ip
        bloqueoIPService.delete(cifradojson.Encrypt_File(req.connection.remoteAddress).toString());
      };

          // get usuario por Ip
          IpBloqueada = 0;
          IpBloqueada = bloqueoIPService.getByIp(cifradojson.Encrypt_File(req.connection.remoteAddress).toString());

   //check if the Ip is blocked
   if (IpBloqueada !== 0) {
    //check if the ip is blocked
    if (IpBloqueada.ip !== 0) {

      logger.info({
        cgSalida: "CI-126",
        descSalida: "No estas autorizado para consumir este recurso"
      });
      return res.status(403).send(cifradojson.Encrypt_File( JSON.stringify({
        codigo: "403.BancaDigital-Usuarios-Gitlab.CI-116",
        mensaje: "Error al realizar la operación",
        folio: validarJson.generarFolio(req.connection.remoteAddress),
        info:
          "https://baz-developer.bancoazteca.com.mx/errors#403.BancaDigital-Usuarios-Gitlab.CI-116",
          cgSalida: "CI-116",
          descSalida: "No estas autorizado para consumir este recurso"
      })));
    }
  };
};
  
    //=============================== END Validar Bloqueo por IP ==========================================//


      var validarToken = {
        hostname: config.get('OauthHostName'),
        port: config.get('OauthPORT'),
        path: config.get('OauthPATH'),
        method: config.get('OauthMethod'),
        headers: {
          "Authorization": authorizationCode
        },
          rejectUnauthorized: false
      };

      logger.info("validarToken => ", validarToken)
  
      validarJson.getJson(validarToken, function(err, result) {

        //log the results
        logger.info("validarToken error => ", err);
        logger.info("validarToken result => ", result);

        // result =>  { error: 'oauth authentication required' } #]
        if (err || result.error == "oauth authentication required") {
          logger.info({ Mensaje: "Incidencia al realizar la operación de validar token en servidor OAuth", Error: err});

              //============================ NUMERO DE INTENTOS ===================================//
              // validar el num de intentos
              let numIntentosIp = numIntentosIpService.getByIp(
                cifradojson.Encrypt_File(req.connection.remoteAddress).toString()
              );

             logger.info("numIntentosIp => ", numIntentosIp);

             if (numIntentosIp > 0) {

              //incrementa el numero de intentos por 1
              numIntentosIpService.update(cifradojson.Encrypt_File(req.connection.remoteAddress).toString(), {
                numIntentos: numIntentosIp + 1,
                date: dateFormat(now, "yyyy-mm-dd HH:MM:ss"),
                ip: cifradojson.Encrypt_File(req.connection.remoteAddress).toString()
              });
                              // bloquear ip cada 10 intentos fallidos
                              if ((numIntentosIp + 1) % 10 === 0) {
                                let verificarIp = bloqueoIPService.getByIp(cifradojson.Encrypt_File(req.connection.remoteAddress).toString());
              
                                if (verificarIp === 0) {
                                  bloqueoIPService.create({
                                    bloqueado: true,
                                    fecha_bloqueo: dateFormat(now, "yyyy-mm-dd HH:MM:ss"),
                                    ip: cifradojson.Encrypt_File(req.connection.remoteAddress).toString()
                                  });
                                }
                              };



            } else if (numIntentosIp === 0) {
              numIntentosIpService.create({
                numIntentos: 1,
                date: dateFormat(now, "yyyy-mm-dd HH:MM:ss"),
                ip: cifradojson.Encrypt_File(req.connection.remoteAddress).toString()
              });
            };

               //============================ END NUMERO DE INTENTOS ===================================//

               return res.status(403).send(cifradojson.Encrypt_File( JSON.stringify({
                codigo: "403.BancaDigital-Usuarios-Gitlab.CI-116",
                mensaje: "Error al realizar la operación",
                folio: validarJson.generarFolio(req.connection.remoteAddress),
                info:
                  "https://baz-developer.bancoazteca.com.mx/errors#403.BancaDigital-Usuarios-Gitlab.CI-116",
                  cgSalida: "CI-116",
                  descSalida: "No estas autorizado para consumir este recurso"
              })));
        };


        ///log the user from the token
        logger.info("La llamada fue realizada desde la aplicacion utilizando OAUTH token con ID de Usuario => ", result.user_id);

        if (result != null) {
          res.locals.numEmpleado = wsDatos.numEmpleado
          next();
        };

      });
};



