const express = require("express");
const router = express.Router();
const validarJson = require("../middleware/validarJson");
const log4js = require("log4js");
const logger = log4js.getLogger("monitoreoRouter");


// Get an item By ID from the database
router.get("/", (req, res) => {


res.status(200).send({ mensaje: "Hola"})
});

module.exports = router;
