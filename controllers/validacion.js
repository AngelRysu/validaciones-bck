const db = require("../config/mysql");


const getValidacion = async (req, res) => {
    const { ui } = req.params;
    const con = await db.getConnection();
    const X_API_KEY = req.headers['api_key'];
    if (X_API_KEY !== process.env.X_API_KEY) {
        return res.status(401).json({ ok: false, msg: 'Falta api key' });
    }
    try {
        const [dataLeak] = await con.query("SELECT * from validaciones WHERE doc_uuid = ? and doc_estado = 'Activo'", [ui]);
        return res.status(200).json({ dataLeak });
    } catch (err) {
        console.log(err);
        return res.status(500).json({ ok: false, msg: 'Algo salió mal' });
    } finally {
        con.release();
    }
};

const deleteValidacion = async (req, res) => {
    const { ui } = req.params;
    const con = await db.getConnection();
    const X_API_KEY = req.headers['api_key'];
    if (X_API_KEY !== process.env.X_API_KEY) {
        return res.status(401).json({ ok: false, msg: 'Falta api key' });
    }
    try {
        const [result] = await con.query("UPDATE validaciones SET doc_estado = 'Inactivo' WHERE doc_uuid = ?", [ui]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ ok: false, msg: 'Validación no encontrada' });
        }
        return res.status(200).json({ ok: true, msg: 'Validación cancelada exitosamente' });
    } catch (err) {
        console.log(err);
        return res.status(500).json({ ok: false, msg: 'Algo salió mal' });
    } finally {
        con.release();
    }
};

module.exports = {
    getValidacion,
    deleteValidacion
}
