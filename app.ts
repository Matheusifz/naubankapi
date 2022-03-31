require("dotenv").config();
require("./config/database").connect();

import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "./model/user";
import verifyToken from "./middleware/auth";

const app = express();

app.use(express.json({ limit: "50mb" }));
app.use(cors());

app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!(email || password || username)) {
      return res.status(400).send("All input are required");
    }
    const oldUser = await User.findOne({ email });
    if (oldUser) {
      return res.send("Email is already in use. Please Log In");
    }

    const encryptedUserPassword = await bcrypt.hash(password, 8);
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

app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  if (!(email && password)) {
    res.status(400).send("Incorrect Password/Email");
  }
  const user = await User.findOne({ email });

  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY ?? "",
      {
        expiresIn: "5h",
      }
    );

    user.token = token;

    return res.status(200).json(user);
  }

  return res.status(400).send("Invalid Credentials");
});

app.get("/welcome", verifyToken, (req: any, res: any) => {
  res.status(200).send("Welcome Dear One");
});

export default app;
