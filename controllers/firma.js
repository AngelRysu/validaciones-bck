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

const firmar_cadena_llave = (cadena, llave, pass) => {
    const signature = crypto.sign(
        "sha256",
        Buffer.from(cadena),
        {
            key: llave,
            passphrase: pass,
            format: 'der',
            type: 'pkcs8'
        }
    );

    return signature.toString('base64');
}

const firma_individual = (req, res) => {
    const { cadena, tipo_firma, password } = req.body; 

    if (!req.file) {
        return res.status(400).json({ ok: false, error: "No se subió ningún archivo de llave" });
    }

    try{
        const llavePrivada = req.file.buffer;

        const sello = firmar_cadena_llave(cadena, llavePrivada, password);

        res.status(200).json({
            ok: true,
            tipo_firma,
            cadenaOrigen: cadena,
            sello: sello
        });
    }catch(err){
        console.log(err);
        res.status(400).json({
            ok: false,
            msg: "firma no valida"
        });
    }
    
}

const firma_multiple = (req, res) => {
    const {cadena, tipo_firma, password} = req.body;

    if (!req.file) {
        return res.status(400).json({ ok: false, error: "No se subió ningún archivo de llave" });
    }

    try{
        const llavePrivada = req.file.buffer;

        const obj_final = [];

        for(individual of cadena){
            const sello = firmar_cadena_llave(individual, llavePrivada, password);
            const objeto_individual = {
                cadenaOrigen: individual,
                tipo_firma,
                sello: sello
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