import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import z from 'zod';
import type { User } from './app/lib/definitions';
import { sql } from '@vercel/postgres';
import { compare } from 'bcrypt';

async function getUser(emailId: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * from users where email = ${emailId}`;
    return user.rows[0];
  } catch (e) {
    console.log(`Failed to fetch user for ${emailId}`, e);
    throw new Error(`Failed to get user`);
  }
}
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          const passwordMatch = compare(password, user.password);
          if(password) return user;
        }
        console.log('Invalid Credentials');
        return null;
      },
    }),
  ],
});
