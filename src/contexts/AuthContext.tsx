"use client";

import React, { createContext, useContext, useEffect, useState } from 'react';
import { 
  User, 
  signInWithPopup, 
  signOut as firebaseSignOut,
  onAuthStateChanged,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendPasswordResetEmail,
  sendEmailVerification,
  updateProfile,
  deleteUser
} from 'firebase/auth';
import { auth, googleProvider } from '@/lib/firebase';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInWithEmail: (email: string, password: string) => Promise<void>;
  signUpWithEmail: (email: string, password: string, displayName: string) => Promise<void>;
  resendVerificationEmail: (email: string, password: string) => Promise<void>;
  resetPassword: (email: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Helper function to sync VERIFIED user with Supabase (only called after email verification)
async function syncUserToSupabase(firebaseUser: User, authProvider: 'google' | 'email'): Promise<boolean> {
  // IMPORTANT: Only sync verified users to database
  if (!firebaseUser.emailVerified && authProvider === 'email') {
    console.log('Skipping database sync - email not verified');
    return false;
  }

  try {
    const response = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        firebase_uid: firebaseUser.uid,
        email: firebaseUser.email,
        display_name: firebaseUser.displayName,
        photo_url: firebaseUser.photoURL,
        is_verified: true, // Only verified users reach this point
        auth_provider: authProvider,
      }),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      console.error('Failed to sync user to Supabase:', errorData);
      return false;
    }
    
    console.log('Verified user synced to Supabase successfully');
    return true;
  } catch (error) {
    console.error('Failed to sync user to Supabase:', error);
    return false;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      // Only set user if:
      // 1. No user (logged out)
      // 2. Google user (always verified)
      // 3. Email user with verified email
      if (!firebaseUser) {
        setUser(null);
        setLoading(false);
        return;
      }

      const isGoogleUser = firebaseUser.providerData[0]?.providerId === 'google.com';
      const isVerified = firebaseUser.emailVerified;

      if (isGoogleUser || isVerified) {
        setUser(firebaseUser);
        // Sync verified users to Supabase
        const provider = isGoogleUser ? 'google' : 'email';
        await syncUserToSupabase(firebaseUser, provider);
      } else {
        // Email user but not verified - don't set as logged in user
        // Sign them out to prevent any access
        await firebaseSignOut(auth);
        setUser(null);
      }
      
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    try {
      const result = await signInWithPopup(auth, googleProvider);
      // Google users are always verified, sync to Supabase
      await syncUserToSupabase(result.user, 'google');
    } catch (error) {
      console.error('Error signing in with Google:', error);
      throw error;
    }
  };

  const signInWithEmail = async (email: string, password: string) => {
    try {
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      
      // Check if email is verified
      if (!userCredential.user.emailVerified) {
        // Sign out the user since email is not verified
        await firebaseSignOut(auth);
        throw { code: 'auth/email-not-verified', message: 'Please verify your email before signing in. Check your inbox for the verification link.' };
      }
      
      // Sync verified user to Supabase
      await syncUserToSupabase(userCredential.user, 'email');
    } catch (error) {
      console.error('Error signing in with email:', error);
      throw error;
    }
  };

  const signUpWithEmail = async (email: string, password: string, displayName: string) => {
    try {
      // Try to create user in Firebase
      // If email already exists but not verified, Firebase will throw 'auth/email-already-in-use'
      // We handle this by trying to sign in and resend verification
      let userCredential;
      
      try {
        userCredential = await createUserWithEmailAndPassword(auth, email, password);
      } catch (createError: unknown) {
        const error = createError as { code?: string };
        
        // If email already in use, check if it's an unverified account
        if (error.code === 'auth/email-already-in-use') {
          try {
            // Try to sign in with the provided credentials
            const existingUser = await signInWithEmailAndPassword(auth, email, password);
            
            if (!existingUser.user.emailVerified) {
              // Unverified account exists - resend verification email
              await sendEmailVerification(existingUser.user, {
                url: window.location.origin + '/login',
              });
              await firebaseSignOut(auth);
              throw { 
                code: 'auth/verification-resent', 
                message: 'An unverified account exists. We\'ve resent the verification email. Please check your inbox.' 
              };
            } else {
              // Account is already verified - they should login instead
              await firebaseSignOut(auth);
              throw { 
                code: 'auth/email-already-in-use', 
                message: 'An account with this email already exists. Please login instead.' 
              };
            }
          } catch (signInError: unknown) {
            const sError = signInError as { code?: string; message?: string };
            // If sign in failed (wrong password), show appropriate error
            if (sError.code === 'auth/wrong-password' || sError.code === 'auth/invalid-credential') {
              throw { 
                code: 'auth/email-already-in-use', 
                message: 'An account with this email already exists. Please login or reset your password.' 
              };
            }
            // Re-throw verification-resent error
            if (sError.code === 'auth/verification-resent') {
              throw sError;
            }
            throw createError; // Re-throw original error
          }
        }
        throw createError;
      }
      
      await updateProfile(userCredential.user, { displayName });
      
      // DO NOT save to Supabase yet - user is not verified
      // User will be saved on first successful verified login
      
      // Send verification email
      try {
        await sendEmailVerification(userCredential.user, {
          url: window.location.origin + '/login',
        });
        console.log('Verification email sent successfully to:', email);
      } catch (emailError) {
        console.error('Failed to send verification email:', emailError);
        // Delete the Firebase user since we couldn't send verification email
        try {
          await deleteUser(userCredential.user);
        } catch (deleteError) {
          console.error('Failed to delete user after email send failure:', deleteError);
        }
        throw { code: 'auth/email-send-failed', message: 'Failed to send verification email. Please try again.' };
      }
      
      // Sign out - user must verify email before they can use the account
      await firebaseSignOut(auth);
    } catch (error) {
      console.error('Error signing up with email:', error);
      throw error;
    }
  };

  const resendVerificationEmail = async (email: string, password: string) => {
    try {
      // Sign in temporarily to resend verification email
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      
      if (userCredential.user.emailVerified) {
        await firebaseSignOut(auth);
        throw { code: 'auth/already-verified', message: 'Your email is already verified. Please login.' };
      }
      
      await sendEmailVerification(userCredential.user, {
        url: window.location.origin + '/login',
      });
      
      await firebaseSignOut(auth);
    } catch (error) {
      console.error('Error sending verification email:', error);
      throw error;
    }
  };

  const resetPassword = async (email: string) => {
    try {
      await sendPasswordResetEmail(auth, email);
    } catch (error) {
      console.error('Error sending password reset email:', error);
      throw error;
    }
  };

  const signOut = async () => {
    try {
      await firebaseSignOut(auth);
    } catch (error) {
      console.error('Error signing out:', error);
      throw error;
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, signInWithGoogle, signInWithEmail, signUpWithEmail, resendVerificationEmail, resetPassword, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
