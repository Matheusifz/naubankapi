require("dotenv").config();
require("./config/database").connect();
import User from "./model/user";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();

app.use(express.json());

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!(email || password || username  )) {
      return res.status(400).send("All input are required");
    }
    const oldUser = await User.findOne({ email });
    if (oldUser) {
      return res.send("User Already Exist. Please Login");
    }

    const encryptedUserPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      username: username,
      email: email.toLowerCase(),
      password: encryptedUserPassword,
    });

    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY ?? "",
      {
        expiresIn: "5h",
      }
    );
    user.token = token;
    res.status(201).json(user);
  } catch (err) {
    console.log("sorry:", err);
  }
});

app.post("/login", (req, res) => {
});

export default app;
