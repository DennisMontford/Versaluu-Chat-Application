import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import cloudinary from "../lib/cloudinary.js";

// Controller for user signup
export const signup = async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    // Validate required fields
    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Validate password length
    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password should be at least 6 characters long" });
    }

    // Check if user with the given email already exists
    const user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "Email already exists" });

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create a new user
    const newUser = new User({
      fullName,
      email,
      password: hashedPassword,
    });

    // If user creation is successful, generate and set a token
    if (newUser) {
      generateToken(newUser._id, res);
      await newUser.save();

      // Respond with the new user's data
      res.status(201).json({
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        profilePic: newUser.profilePic,
      });
    } else {
      // Respond with an error if user data is invalid
      res.status(400).json({ message: "Invalid user data" });
    }
  } catch (error) {
    // Log and respond with the error
    console.log("Error in signup controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Controller for user login
export const login = async (req, res) => {
  const { email, password } = req.body;
  try {
    // Find the user by email
    const user = await User.findOne({ email });

    // If user is not found, respond with invalid credentials
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Compare the provided password with the stored hash
    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    // If password is incorrect, respond with invalid credentials
    if (!isPasswordCorrect) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate and set a token for the logged-in user
    generateToken(user._id, res);

    // Respond with the user's data
    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      email: user.email,
      profilePic: user.profilePic,
    });
  } catch (error) {
    // Log and respond with the error
    console.log("Error in login controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Controller for user logout
export const logout = (req, res) => {
  try {
    // Clear the JWT cookie to log the user out
    res.cookie("jwt", "", {
      maxAge: 0,
    });
    // Respond with a success message
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    // Log and respond with the error
    console.log("Error in logout controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Controller to update user profile picture
export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user._id;

    // Validate that profile picture is provided
    if (!profilePic) {
      return res.status(400).json({ message: "Profile picture is required" });
    }

    // Upload the profile picture to Cloudinary
    const uploadResponse = await cloudinary.uploader.upload(profilePic);
    // Update the user's profile picture URL in the database
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profilePic: uploadResponse.secure_url },
      { new: true }
    );

    // Respond with the updated user data
    res.status(200).json(updatedUser);
  } catch (error) {
    // Log and respond with the error
    console.log("Error in updateProfile controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Controller to check user authentication status
export const checkAuth = (req, res) => {
  try {
    // Respond with the authenticated user's data
    res.status(200).json(req.user);
  } catch (error) {
    // Log and respond with the error
    console.log("Error in checkAuth controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
