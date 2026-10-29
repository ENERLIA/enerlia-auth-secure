import { getSessionFromCtx } from "better-auth/api";

/** Partie du contexte Better Auth utile pour retrouver l'utilisateur pendant l'étape 2FA. */
export type ContexteDeuxFacteurs = {
  context: {
    secret: string;
    internalAdapter: {
      findVerificationValue(identifier: string): Promise<{ value: string; expiresAt?: Date | string } | null>;
    };
    createAuthCookie(nom: string): { name: string };
  };
  getSignedCookie(nom: string, secret: string): Promise<string | null | false>;
};

/**
 * Utilisateur concerné par une route 2FA : celui de la session ouverte, sinon
 * celui de l'étape 2FA en cours (cookie `two_factor` posé après le mot de passe).
 */
export async function utilisateurEn2fa(ctx: ContexteDeuxFacteurs): Promise<string | null> {
  try {
    const session = await getSessionFromCtx(ctx as never);
    if (session?.user?.id) return session.user.id;
  } catch {
    // Pas de session : connexion en cours, on lit le cookie de l'étape 2FA.
  }
  try {
    const cookie = ctx.context.createAuthCookie("two_factor");
    const jeton = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
    if (!jeton) return null;
    const verification = await ctx.context.internalAdapter.findVerificationValue(jeton);
    return verification?.value ?? null;
  } catch {
    return null;
  }
}
