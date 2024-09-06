// server.js
import express from "express";
import cookieParser from "cookie-parser";
import session from "express-session";
import cors from "cors";
import { PORT } from "./src/config/env.js";
import { routesAuth } from "./src/routes/auth.routes.js";
import morgan from "morgan";

const app = express();

app.use(
  cors({
    origin: [
      "http://localhost:5500",
      "http://localhost:3000",
      "http://127.0.0.1:3000",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: "session_secret_key", // Cambia esto por una clave secreta en producción
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Usar 'true' si usas HTTPS
  })
);

app.use("/api", routesAuth);

// // Endpoint de inicio de sesión (login)
// app.post("/login", async (req, res) => {});

// // Endpoint para validar la sesión
// app.get("/session", validarJwt, (req, res) => {});

// // Endpoint de cierre de sesión (logout)
// app.post("/logout", (req, res) => {});

// Servidor escuchando
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
