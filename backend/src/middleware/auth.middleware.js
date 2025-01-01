import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import ApplicationError from "../lib/error.js";

export const authMiddleware = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      throw new ApplicationError("Unauthorized - No Token Provided", 401);
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (!decoded) {
      throw new ApplicationError("Unauthorized - Invalid Token", 401);
    }

    const user = await User.findById(decoded.userId);
    if (!user) {
      throw new ApplicationError("Unauthorized - No User Found", 401);
    }

    req.user = user;
    next();
  } catch (error) {
    if (error instanceof ApplicationError) {
      return res.status(error.statusCode).json({
        message: error.message,
      });
    }
    res.status(500).json({
      message: "Internal Server error",
    });
  }
};
