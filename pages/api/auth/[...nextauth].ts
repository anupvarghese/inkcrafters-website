import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import clientPromise from "../../../lib/mongodb";

export const authOptions = {
  pages: {
    error: "/auth/signin", // Error code passed in query string as ?error=
    signIn: "/auth/signin",
  },
  secret: process.env.NEXTAUTH_SECRET,
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "Username", type: "text", placeholder: "jsmith" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const client = await clientPromise;
        const usersCollection = client.db().collection("users");

        const username = credentials.username.toLowerCase();
        const user = await usersCollection.findOne({ username });

        if (!user) {
          throw new Error("No user found");
        }

        const passwordIsValid = await bcrypt.compare(
          credentials.password,
          user.password
        );

        if (!passwordIsValid) {
          throw new Error("Invalid password");
        }

        return {
          id: user._id.toString(),
          name: user.name,
          jwt: {
            secret: process.env.NEXTAUTH_SECRET,
          },
        };
      },
    }),
  ],
};

export default NextAuth(authOptions);
