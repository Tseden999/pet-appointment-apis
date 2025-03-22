const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

// Service to handle user-related logic

// Sign up a new user
exports.signup = async (email, password, name) => {
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new Error('User already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = new User({ email, password: hashedPassword, name });

    await newUser.save();
    return newUser;
  } catch (error) {
    throw error;
  }
};

// User login
exports.login = async (email, password) => {
  try {
    const user = await User.findOne({ email });
    if (!user) {
      throw new Error('Invalid credentials');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new Error('Invalid credentials');
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return token;
  } catch (error) {
    throw error;
  }
};

// Get user profile
exports.getProfile = async (userId) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  } catch (error) {
    throw error;
  }
};

// Edit user profile
exports.editProfile = async (userId, updatedData) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    if (updatedData.name) user.name = updatedData.name;
    if (updatedData.email) user.email = updatedData.email;

    await user.save();
    return user;
  } catch (error) {
    throw error;
  }
};

// Delete user profile
exports.deleteProfile = async (userId) => {
  try {
    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      throw new Error('User not found');
    }
    return user;
  } catch (error) {
    throw error;
  }
};
