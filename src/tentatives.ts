import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { type ContexteDeuxFacteurs, utilisateurEn2fa } from "./deux-facteurs";
import { codeErreur, estErreurApi } from "./erreurs";
import { type EtatTentatives, SCHEMA_TENTATIVE, type StockageTentatives, stockageBase } from "./stockage";

export { type EtatTentatives, MODELE_TENTATIVE, type StockageTentatives, stockageMemoire } from "./stockage";

/**
 * Protection contre les attaques par force brute, selon le référentiel Enerlia
 * « Sécurité des comptes et des connexions » v2.3, section 3 :
 * - délai croissant après chaque échec pour un même compte, à partir du 3e ;
 * - blocage temporaire du compte après 10 échecs consécutifs (15 min), levé
 *   aussi par une réinitialisation ou un changement du mot de passe ;
 * - même protection pour les codes 2FA (TOTP, code par e-mail, codes de secours) ;
 * - aucun blocage par adresse IP : le compteur est rattaché au compte, et le
 *   blocage ne touche que le compte visé. Un attaquant qui change d'adresse IP
 *   ne remet pas le compteur à zéro, et les collègues qui partagent la même
 *   connexion ne sont jamais gênés. La limite `rateLimit` de Better Auth, qui
 *   compte par adresse IP, doit être désactivée (voir le README).
 *
 * Les essais sur une adresse inconnue sont comptés et traités comme les autres :
 * la réponse ne révèle jamais si un compte existe.
 */

export type OptionsTentatives = {
  /**
   * Stockage des compteurs. Sans valeur, le plugin ajoute la table
   * `enerliaTentative` à la base Better Auth. Avec le composant Convex
   * `@convex-dev/better-auth` non installé en local, fournir un stockage
   * qui écrit dans une table de l'application (voir le README).
   */
  stockage?: StockageTentatives;
  /** Échecs consécutifs avant blocage. 10 par défaut. */
  echecsAvantBlocage?: number;
  /** Durée du blocage, en millisecondes. 15 minutes par défaut. */
  dureeBlocageMs?: number;
  /** Nombre d'échecs à partir duquel un délai est imposé. 3 par défaut. */
  echecsAvantDelai?: number;
  /** Délai imposé après le premier palier, doublé à chaque échec suivant. 1 seconde par défaut. */
  delaiInitialMs?: number;
  /** Délai maximal entre deux essais. 30 secondes par défaut. */
  delaiMaxMs?: number;
  /** Au-delà de cette durée sans échec, le compteur repart de zéro. 24 h par défaut. */
  oubliApresMs?: number;
  /** Routes de connexion par mot de passe dont le corps contient `email`. */
  cheminsMotDePasse?: string[];
  /** Routes de vérification d'un code 2FA. */
  chemins2fa?: string[];
};

export const MESSAGE_COMPTE_BLOQUE =
  "Trop de tentatives. Réessayez dans 15 minutes ou réinitialisez votre mot de passe.";
export const MESSAGE_DELAI = "Trop de tentatives rapprochées. Patientez quelques secondes avant de réessayer.";

const CHEMINS_MOT_DE_PASSE = ["/sign-in/email"];
const CHEMINS_2FA = ["/two-factor/verify-totp", "/two-factor/verify-otp", "/two-factor/verify-backup-code"];
/**
 * Routes qui définissent un nouveau mot de passe : elles débloquent le compte.
 * - lien de réinitialisation : dès que le lien est reconnu valide (il prouve
 *   l'accès à la boîte mail), avant même le traitement ;
 * - les autres : après une réussite.
 */
const CHEMIN_LIEN_REINITIALISATION = "/reset-password";
const CHEMINS_REINITIALISATION_PAR_EMAIL = new Set(["/email-otp/reset-password"]);
const CHEMINS_CHANGEMENT_CONNECTE = new Set(["/change-password", "/set-password"]);
const CHEMIN_ADMIN = "/admin/set-user-password";
/** Erreurs 401 qui ne sont pas un mauvais mot de passe ou un mauvais code. */
const ERREURS_NON_COMPTEES = new Set(["INVALID_TWO_FACTOR_COOKIE"]);

export function cleMotDePasse(email: string): string {
  return `mdp:${email.trim().toLowerCase()}`;
}

export function cle2fa(userId: string): string {
  return `2fa:${userId}`;
}

/** Délai à respecter avant l'essai suivant, selon le nombre d'échecs consécutifs. */
export function delaiAvantEssai(
  echecs: number,
  options: Pick<OptionsTentatives, "echecsAvantDelai" | "delaiInitialMs" | "delaiMaxMs"> = {},
): number {
  const palier = options.echecsAvantDelai ?? 3;
  if (echecs < palier) return 0;
  const initial = options.delaiInitialMs ?? 1000;
  const max = options.delaiMaxMs ?? 30_000;
  return Math.min(initial * 2 ** (echecs - palier), max);
}

/** Nouvel état après un échec. */
export function apresEchec(
  etat: EtatTentatives | null,
  maintenant: number,
  options: Pick<OptionsTentatives, "echecsAvantBlocage" | "dureeBlocageMs" | "oubliApresMs"> = {},
): EtatTentatives {
  const oubli = options.oubliApresMs ?? 24 * 60 * 60 * 1000;
  const repart =
    !etat ||
    maintenant - etat.dernierEchec > oubli ||
    (etat.bloqueJusqua > 0 && etat.bloqueJusqua <= maintenant);
  const echecs = (repart ? 0 : etat.echecs) + 1;
  const seuil = options.echecsAvantBlocage ?? 10;
  const duree = options.dureeBlocageMs ?? 15 * 60 * 1000;
  return { echecs, dernierEchec: maintenant, bloqueJusqua: echecs >= seuil ? maintenant + duree : 0 };
}

/** Refus à opposer avant un essai, ou `null` si l'essai est autorisé. */
export function refusAvantEssai(
  etat: EtatTentatives | null,
  maintenant: number,
  options: Omit<OptionsTentatives, "stockage"> = {},
): { raison: "bloque" | "delai"; attenteMs: number } | null {
  if (!etat) return null;
  if (etat.bloqueJusqua > maintenant) return { raison: "bloque", attenteMs: etat.bloqueJusqua - maintenant };
  if (etat.bloqueJusqua > 0) return null;
  if (maintenant - etat.dernierEchec > (options.oubliApresMs ?? 24 * 60 * 60 * 1000)) return null;
  const attente = etat.dernierEchec + delaiAvantEssai(etat.echecs, options) - maintenant;
  return attente > 0 ? { raison: "delai", attenteMs: attente } : null;
}

type ContexteRequete = ContexteDeuxFacteurs & {
  path?: string;
  body?: Record<string, unknown>;
  query?: Record<string, unknown>;
  context: ContexteDeuxFacteurs["context"] & {
    returned?: unknown;
    newSession?: { user?: { id?: string } } | null;
    adapter: unknown;
    internalAdapter: ContexteDeuxFacteurs["context"]["internalAdapter"] & {
      findUserById(id: string): Promise<{ id?: string; email?: string } | null>;
      findUserByEmail(email: string): Promise<{ user?: { id?: string; email?: string } } | null>;
    };
  };
};

function emailDuCorps(ctx: ContexteRequete): string | null {
  const email = ctx.body?.email;
  return typeof email === "string" && email.trim() ? email : null;
}

async function utilisateurConnecte(ctx: ContexteRequete): Promise<{ id?: string; email?: string } | null> {
  try {
    const session = await getSessionFromCtx(ctx as never);
    return session?.user ?? null;
  } catch {
    return null;
  }
}

/** Utilisateur visé par un lien de réinitialisation encore valide, ou `null`. */
async function utilisateurDuLien(ctx: ContexteRequete): Promise<{ id?: string; email?: string } | null> {
  const jeton = ctx.body?.token ?? ctx.query?.token;
  if (typeof jeton !== "string" || !jeton) return null;
  try {
    const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${jeton}`);
    if (!verification?.value) return null;
    if (verification.expiresAt && new Date(verification.expiresAt).getTime() < Date.now()) return null;
    return await ctx.context.internalAdapter.findUserById(verification.value);
  } catch {
    return null;
  }
}

/** Plugin Better Auth : délai croissant et blocage temporaire par compte. */
export const tentativesEnerlia = (options: OptionsTentatives = {}) => {
  const cheminsMotDePasse = new Set(options.cheminsMotDePasse ?? CHEMINS_MOT_DE_PASSE);
  const chemins2fa = new Set(options.chemins2fa ?? CHEMINS_2FA);
  let stockageParDefaut: StockageTentatives | null = null;
  const stockage = (ctx: ContexteRequete): StockageTentatives => {
    if (options.stockage) return options.stockage;
    stockageParDefaut ??= stockageBase(ctx.context.adapter);
    return stockageParDefaut;
  };

  const cleAvant = async (ctx: ContexteRequete): Promise<string | null> => {
    if (ctx.path && cheminsMotDePasse.has(ctx.path)) {
      const email = emailDuCorps(ctx);
      return email ? cleMotDePasse(email) : null;
    }
    if (ctx.path && chemins2fa.has(ctx.path)) {
      const userId = await utilisateurEn2fa(ctx);
      return userId ? cle2fa(userId) : null;
    }
    return null;
  };

  const debloquer = async (ctx: ContexteRequete, utilisateur: { id?: string; email?: string } | null) => {
    if (!utilisateur) return;
    try {
      if (utilisateur.email) await stockage(ctx).effacer(cleMotDePasse(utilisateur.email));
      if (utilisateur.id) await stockage(ctx).effacer(cle2fa(utilisateur.id));
    } catch {
      // Le déblocage est un confort : il ne doit jamais faire échouer le changement de mot de passe.
    }
  };

  const estCheminDeblocage = (chemin: string) =>
    chemin === CHEMIN_LIEN_REINITIALISATION ||
    chemin === CHEMIN_ADMIN ||
    CHEMINS_REINITIALISATION_PAR_EMAIL.has(chemin) ||
    CHEMINS_CHANGEMENT_CONNECTE.has(chemin);

  const plugin = {
    id: "enerlia-tentatives",
    hooks: {
      before: [
        {
          matcher: (ctx: { path?: string }) => ctx.path === CHEMIN_LIEN_REINITIALISATION,
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            await debloquer(c, await utilisateurDuLien(c));
          }),
        },
        {
          matcher: (ctx: { path?: string }) =>
            !!ctx.path && (cheminsMotDePasse.has(ctx.path) || chemins2fa.has(ctx.path)),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            const cle = await cleAvant(c);
            if (!cle) return;
            const refus = refusAvantEssai(await stockage(c).lire(cle), Date.now(), options);
            if (!refus) return;
            const secondes = Math.max(1, Math.ceil(refus.attenteMs / 1000));
            throw new APIError(
              "TOO_MANY_REQUESTS",
              refus.raison === "bloque"
                ? { message: MESSAGE_COMPTE_BLOQUE, code: "COMPTE_TEMPORAIREMENT_BLOQUE" }
                : { message: MESSAGE_DELAI, code: "TENTATIVE_TROP_RAPIDE" },
              { "Retry-After": String(secondes) },
            );
          }),
        },
      ],
      after: [
        {
          matcher: (ctx: { path?: string }) =>
            !!ctx.path && ctx.path !== CHEMIN_LIEN_REINITIALISATION && estCheminDeblocage(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            if (estErreurApi(c.context.returned) || !c.path) return;
            if (CHEMINS_CHANGEMENT_CONNECTE.has(c.path)) return debloquer(c, await utilisateurConnecte(c));
            if (c.path === CHEMIN_ADMIN) {
              const userId = c.body?.userId;
              if (typeof userId === "string") await debloquer(c, await c.context.internalAdapter.findUserById(userId));
              return;
            }
            const email = emailDuCorps(c);
            if (!email) return;
            const trouve = await c.context.internalAdapter.findUserByEmail(email).catch(() => null);
            await debloquer(c, trouve?.user ?? { email });
          }),
        },
        {
          matcher: (ctx: { path?: string }) =>
            !!ctx.path && (cheminsMotDePasse.has(ctx.path) || chemins2fa.has(ctx.path)),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            const resultat = c.context.returned;
            if (estErreurApi(resultat)) {
              const code = codeErreur(resultat);
              if (resultat.statusCode !== 401 || (code && ERREURS_NON_COMPTEES.has(code))) return;
              const cle = await cleAvant(c);
              if (!cle) return;
              const etat = await stockage(c).lire(cle);
              await stockage(c).ecrire(cle, apresEchec(etat, Date.now(), options));
              return;
            }
            // Réussite : le mot de passe ou le code était bon, le compteur repart de zéro.
            if (c.path && cheminsMotDePasse.has(c.path)) {
              const email = emailDuCorps(c);
              if (email) await stockage(c).effacer(cleMotDePasse(email));
              return;
            }
            const userId =
              c.context.newSession?.user?.id ??
              (resultat as { user?: { id?: string } } | null | undefined)?.user?.id ??
              (await utilisateurEn2fa(c));
            if (userId) await stockage(c).effacer(cle2fa(userId));
          }),
        },
      ],
    },
    ...(options.stockage ? {} : { schema: SCHEMA_TENTATIVE }),
  } satisfies BetterAuthPlugin;
  return plugin;
};
