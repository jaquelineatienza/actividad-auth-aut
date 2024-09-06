import jwt from "jsonwebtoken";
import { SECRET_KEY } from "../src/config/env.js";
import { connectDB } from "../src/db/database.js";

// Middleware para verificar el token JWT
export const validarJwt = async (req, res, next) => {
  console.log(req.session);
  console.log("-----------");
  console.log(req.cookies);

  const token = req.cookies.authToken || req.session.token;

  if (!token) {
    return res.status(403).json({ message: "Token no proporcionado" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);

    const connection = await connectDB();

    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE id = ?",
      [decoded.userId]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Token inválido" });
    }

    const user = rows[0];

    req.user = user;

    next();
  } catch (error) {
    console.error(
      "Error en la verificación del token o consulta de base de datos:",
      error
    );
    return res
      .status(401)
      .json({ message: "Token inválido o error en la base de datos" });
  }
};
