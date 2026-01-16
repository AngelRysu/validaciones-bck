const crypto = require('crypto');
/**
 * Genera una firma electrónica (sello) a partir de una cadena y una llave privada.
 * @param {string} cadenaOrigen - Los datos que se van a firmar.
 * @param {string} privateKeyPem - La llave privada en formato PEM.
 * @returns {string} - La firma electrónica resultante en Base64.
 */
const firmar_cadena = (cadena, llave) => {
    // 1. Crear el objeto de firma usando el algoritmo deseado
    const sign = crypto.createSign('SHA256');

    // 2. Cargar la cadena de origen
    sign.update(cadena);
    sign.end();

    // 3. Firmar con la llave privada y devolver en Base64
    const signature = sign.sign(llave, 'base64');
    
    return signature;
}

const firma_individual = (req, res) => {
    const { cadena } = req.body; 

    // El archivo de la llave está en req.file
    if (!req.file) {
        return res.status(400).json({ ok: false, error: "No se subió ningún archivo de llave" });
    }

    try{
        const llavePrivadaPem = req.file.buffer.toString('utf8');

        const sello = firmar_cadena(cadena, llavePrivadaPem);

        res.status(200).json({
            ok: true,
            cadenaOrigen: cadena,
            sello: sello
        });
    }catch(err){
        res.status(400).json({
            ok: false,
            msg: "firma no valida"
        });
    }
    
}

const firma_multiple = (req, res) => {
    const {cadena} = req.body;

    if (!req.file) {
        return res.status(400).json({ ok: false, error: "No se subió ningún archivo de llave" });
    }

    try{
        const llavePrivadaPem = req.file.buffer.toString('utf8');

        const obj_final = [];

        for(individual of cadena){
            const objeto_individual = {
                cadenaOrigen: individual,
                sello: firmar_cadena(individual, llavePrivadaPem)
            }
            obj_final.push(objeto_individual);
        }

       res.status(200).json({ok: true, data: obj_final});

    }catch(err){
        console.log(err);
        res.status(400).json({
            ok: false,
            msg: "firma no valida"
        });
    }

}

module.exports = {
    firma_individual,
    firma_multiple
}