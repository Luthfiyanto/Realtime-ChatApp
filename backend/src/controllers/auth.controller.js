import bcrypt from "bcrypt";
import cloudinary from "../lib/cloudinary.js";
import User from "../models/user.model.js";
import { generateToken } from "../lib/utils.js";
import ApplicationError from "../lib/error.js";

export const signup = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    if (!name || !email || !password) {
      throw new ApplicationError("Please fill in all fields", 400);
    }

    if (password.length < 6) {
      throw new ApplicationError("Password must be at least 6 characters long", 400);
    }

    const user = await User.findOne({ email });
    if (user) {
      throw new ApplicationError("User already exists", 400);
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
    });

    if (newUser) {
      generateToken(newUser._id, res);
      await newUser.save();

      res.status(201).json({
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        profilPic: newUser.profilePic,
      });
      return;
    } else {
      throw new ApplicationError("Failed to create user", 400);
    }
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

export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      throw new ApplicationError("Please fill in all fields", 400);
    }
    const user = await User.findOne({ email });
    if (!user) {
      throw new ApplicationError("Invalid Credential", 400);
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new ApplicationError("Invalid Credential", 400);
    }

    generateToken(user._id, res);
    res.status(200).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      profilPic: user.profilPic,
    });
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

export const logout = (req, res) => {
  try {
    res.cookie("token", "", { maxAge: 0 });
    res.status(200).json({
      message: "Logged out successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Internal Server error",
    });
  }
};

export const updateProfile = async (req, res) => {
  try {
    const { profilPic } = req.body;
    const userId = req.user._id;

    if (!profilPic) {
      throw new ApplicationError("Please provide a profile picture", 400);
    }
    const uploadResponse = await cloudinary.uploader.upload(profilPic);
    const updatedUser = await User.findByIdAndUpdate(userId, { profilPic: uploadResponse.secure_url }, { new: true });

    res.status(200).json(updatedUser);
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

export const checkAuth = (req, res) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    res.status(500).json({
      message: "Internal Server error",
    });
  }
};
