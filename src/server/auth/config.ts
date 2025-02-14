import { PrismaAdapter } from "@auth/prisma-adapter";
import { type DefaultSession, type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import { ZodError } from "zod";
import { signInSchema } from "~/schemas/auth";

import { db } from "~/server/db";

/**
 * Module augmentation for `next-auth` types. Allows us to add custom properties to the `session`
 * object and keep type safety.
 *
 * @see https://next-auth.js.org/getting-started/typescript#module-augmentation
 */
declare module "next-auth" {
  interface Session extends DefaultSession {
    user: {
      id: string;
      // ...other properties
      // role: UserRole;
    } & DefaultSession["user"];
  }

  // interface User {
  //   // ...other properties
  //   // role: UserRole;
  // }
}

/**
 * Options for NextAuth.js used to configure adapters, providers, callbacks, etc.
 *
 * @see https://next-auth.js.org/configuration/options
 */
export const authConfig = {
  providers: [
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        console.log(credentials, "credentials");
        try {
          let user = null;
          const { email, password } = await signInSchema.parseAsync(credentials)
          // logic to salt and hash password
          
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
          const hashedPassword = await bcrypt.hash(password, 10)
          
          // logic to check if user exists
          const user = await db.user.findUnique({
            where: { email },
          });
          if (!user) {
            throw new Error("User not found");
          }
          // const isPasswordValid = await bcrypt.compare(password, user.password);
          // if (!isPasswordValid) {
          //   throw new Error("Invalid password");
          // }
          return user;
        } catch (error: unknown) {
          if (error instanceof ZodError) {
            throw new Error(error.message);
          }
        }
        return null;
      },
    }),
  ],
  adapter: PrismaAdapter(db),
  callbacks: {
    session: ({ session, user }) => ({
      ...session,
      user: {
        ...session.user,
        id: user.id,
      },
    }),
  },
} satisfies NextAuthConfig;
