import { connectDB } from "../db/database.js";
import generarJwt from "../helpers/generar-jwt.js";

//controllador para iniciar session

export const login = async (req, res) => {
  const { username, password } = req.body;

  try {
    // Establecer conexión con la base de datos
    const connection = await connectDB();

    // Realizar consulta para verificar el usuario
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE username = ? AND password = ?",
      [username, password]
    );

    // Verificar si se encontró el usuario
    if (rows.length === 0) {
      return res.status(401).json({ message: "Credenciales incorrectas" });
    }

    const user = rows[0];

    // Generar token JWT
    const token = await generarJwt(user.id);

    // Almacenar el token en la sesión del servidor
    req.session.token = token;

    // Almacenar el token en una cookie segura
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: false,
      maxAge: 3600000, // 1 hora
    });

    return res.json({
      message: "Inicio de sesión exitoso",
      user: { id: user.id, username: user.username },
    });
  } catch (error) {
    console.error("Error en el inicio de sesión:", error);
    return res.status(500).json({ message: "Error inesperado" });
  }
};

//controlador para validar la sesion
export const session = (req, res) => {
  console.log(req.user);
  return res.json({
    message: "Acceso permitido a área protegida",
    user: req.user,
  });
};

export const register = async (req, res) => {
  const { username, password } = req.body;

  try {
    // Establecer conexión con la base de datos
    const connection = await connectDB();

    // Verificar si el nombre de usuario ya existe
    const [existUser] = await connection.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (existUser.length > 0) {
      return res
        .status(409)
        .json({ message: "El nombre de usuario ya está en uso" });
    }

    // Insertar el nuevo usuario en la base de datos
    const [result] = await connection.execute(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, password]
    );

    if (result.affectedRows === 1) {
      return res.status(201).json({ message: "Usuario creado exitosamente" });
    } else {
      return res.status(500).json({ message: "Error al crear el usuario" });
    }
  } catch (error) {
    console.error("Error al registrar el usuario:", error);
    return res.status(500).json({ message: "Error inesperado" });
  }
};
//controlador para cerrar la session
export const logout = async (req, res) => {
  try {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ message: "Error al cerrar sesión" });
      }

      res.clearCookie("authToken");
      return res.json({ message: "Cierre de sesión exitoso" });
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Error Inesperado" });
  }
};
