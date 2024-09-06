import { connectDB } from "../db/database.js";
import generarJwt from "../helpers/generar-jwt.js";

//controllador para iniciar session
export const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = database.user.find(
      (user) => user.username === username && user.password === password
    );

    // Validación de usuario
    if (!user) {
      return res.status(401).json({ message: "Credenciales incorrectas" });
    }

    // Generar token JWT
    const token = await generarJwt(user.id);

    // Almacenar el token en la sesión del servidor
    req.session.token = token;

    // Almacenar el token en una cookie segura
    res.cookie("authToken", token, {
      httpOnly: true,
      secure: false,
      maxAge: 3600000,
    });

    return res.json({ message: "Inicio de sesión exitoso" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Error Inesperado" });
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
