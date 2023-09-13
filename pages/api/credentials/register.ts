import bcrypt from "bcryptjs";
import clientPromise from "../../../lib/mongodb";

async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
}

async function createUser(username, password, res) {
  const client = await clientPromise;

  const usersCollection = client.db().collection("users");
  const hashedPassword = await hashPassword(password);
  const existingUser = await usersCollection.findOne({ username });
  if (existingUser) {
    throw new Error("User already exists");
  }

  try {
    await usersCollection.insertOne({ username, password: hashedPassword });
    res.status(200).json({ message: "User added" });
  } catch (error) {
    res.status(500).json({ message: "Error adding user" });
  }
}

export default function handler(req, res) {
  const { username, password } = req.body;
  if (req.method === "POST") {
    if (!username || !password) {
      res.status(400).json({ message: "Missing username or password" });
    } else {
      return createUser(username, password, res);
    }
  } else {
    res.status(400).json({ message: "Invalid request" });
  }
}
