import User from "../models/user.model.js";
import Message from "../models/message.model.js";
import cloudinary from "../lib/cloudinary.js";
import { getReceiverSocketId, io } from "../lib/socket.js";

// Controller to get users for the sidebar (excluding the logged-in user)
export const getUsersForSidebar = async (req, res) => {
  try {
    // Get the ID of the logged-in user
    const loggedInUserId = req.user._id;
    // Find all users except the logged-in user, and exclude the password field
    const filteredUsers = await User.find({
      _id: { $ne: loggedInUserId },
    }).select("-password");

    // Respond with the filtered users
    res.status(200).json(filteredUsers);
  } catch (error) {
    // Log and respond with the error
    console.log("Error in getUsersForSidebar", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Controller to get messages between two users
export const getMessages = async (req, res) => {
  try {
    // Extract the ID of the user to chat with from the request parameters
    const { id: userToChatId } = req.params;
    // Get the ID of the logged-in user
    const myId = req.user._id;

    // Find messages where either the logged-in user is the sender and the other user is the receiver, or vice versa
    const messages = await Message.find({
      $or: [
        { senderId: myId, receiverId: userToChatId },
        { senderId: userToChatId, receiverId: myId },
      ],
    });

    // Respond with the messages
    res.status(200).json(messages);
  } catch (error) {
    // Log and respond with the error
    console.log("Error in getMessages controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Controller to send a message
export const sendMessage = async (req, res) => {
  try {
    // Extract text and image from the request body
    const { text, image } = req.body;
    // Extract the receiver's ID from the request parameters
    const { id: receiverId } = req.params;

    // Get the sender's ID from the authenticated user
    const senderId = req.user._id;

    let imageUrl;
    // Upload image to Cloudinary if provided
    if (image) {
      const uploadResponse = await cloudinary.uploader.upload(image);
      imageUrl = uploadResponse.secure_url;
    }

    // Create a new message
    const newMessage = new Message({
      senderId,
      receiverId,
      text,
      image: imageUrl,
    });

    // Save the new message to the database
    await newMessage.save();

    // Get the socket ID of the receiver
    const receiverSocketId = getReceiverSocketId(receiverId);

    // If the receiver is online, emit the new message to their socket
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("message", newMessage);
    }

    // Respond with the new message
    res.status(201).json(newMessage);
  } catch (error) {
    // Log and respond with the error
    console.log("Error in sendMessage controller", error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};
