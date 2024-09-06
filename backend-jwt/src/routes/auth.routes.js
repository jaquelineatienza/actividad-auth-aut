import { Router } from "express";
import { validarJwt } from "../../middlewares/validar-jwt.js";
import {
  login,
  logout,
  register,
  session,
} from "../controllers/auth.controllers.js";

export const routesAuth = Router();

routesAuth.post("/login", login);

routesAuth.get("/session", validarJwt, session);

routesAuth.post("/logout", logout);

routesAuth.post("/register", register);
