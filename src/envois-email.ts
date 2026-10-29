import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { type ContexteDeuxFacteurs, utilisateurEn2fa } from "./deux-facteurs";
import { type EtatTentatives, SCHEMA_TENTATIVE, type StockageTentatives, stockageBase } from "./stockage";

/**
 * Limite des envois d'e-mails, selon le référentiel Enerlia « Sécurité des
 * comptes et des connexions » v2.3, section 3 : les demandes de lien ou de code
 * par e-mail (mot de passe oublié, code 2FA, renvoi d'invitation…) sont
 * limitées à 3 en 10 minutes par adresse e-mail, pour éviter d'inonder une
 * boîte mail. La 4e demande est refusée et aucun e-mail n'est envoyé.
 *
 * Le compteur est rattaché à l'adresse demandée, jamais à l'adresse IP. Les
 * adresses inconnues sont comptées comme les autres : la réponse ne révèle pas
 * si un compte existe.
 */

export type RouteEnvoiEmail = {
  /** Chemin Better Auth, par exemple `/invitation/resend`. */
  chemin: string;
  /** Champ du corps qui contient l'adresse e-mail destinataire. */
  champ: string;
};

export type OptionsEnvoisEmail = {
  /** Stockage des compteurs. Sans valeur : la table `enerliaTentative` de la base Better Auth. */
  stockage?: StockageTentatives;
  /** Demandes autorisées par adresse sur la fenêtre. 3 par défaut. */
  maxDemandes?: number;
  /** Fenêtre de comptage, en millisecondes. 10 minutes par défaut. */
  fenetreMs?: number;
  /** Routes propres à l'application qui envoient un e-mail (renvoi d'invitation…). */
  routesSupplementaires?: RouteEnvoiEmail[];
};

export const ROUTES_ENVOI_EMAIL: RouteEnvoiEmail[] = [
  { chemin: "/request-password-reset", champ: "email" },
  { chemin: "/email-otp/request-password-reset", champ: "email" },
  { chemin: "/forget-password/email-otp", champ: "email" },
  { chemin: "/email-otp/send-verification-otp", champ: "email" },
  { chemin: "/send-verification-email", champ: "email" },
  { chemin: "/sign-in/magic-link", champ: "email" },
];

/** Code 2FA envoyé par e-mail : l'adresse n'est pas dans le corps, on compte par utilisateur. */
const CHEMIN_CODE_2FA = "/two-factor/send-otp";

export const MESSAGE_TROP_DE_DEMANDES = "Trop de demandes pour cette adresse e-mail. Réessayez dans quelques minutes.";

export function cleEnvoiEmail(email: string): string {
  return `envoi:${email.trim().toLowerCase()}`;
}

export function cleEnvoi2fa(userId: string): string {
  return `envoi-2fa:${userId}`;
}

/**
 * Compte une demande d'envoi sur une fenêtre fixe. Renvoie le nouvel état à
 * enregistrer si la demande est acceptée, ou le temps d'attente si elle est refusée.
 */
export function compterDemande(
  etat: EtatTentatives | null,
  maintenant: number,
  options: Pick<OptionsEnvoisEmail, "maxDemandes" | "fenetreMs"> = {},
): { accepte: true; etat: EtatTentatives } | { accepte: false; attenteMs: number } {
  const max = options.maxDemandes ?? 3;
  const fenetre = options.fenetreMs ?? 10 * 60 * 1000;
  if (!etat || etat.bloqueJusqua <= maintenant) {
    return { accepte: true, etat: { echecs: 1, dernierEchec: maintenant, bloqueJusqua: maintenant + fenetre } };
  }
  if (etat.echecs >= max) return { accepte: false, attenteMs: etat.bloqueJusqua - maintenant };
  return { accepte: true, etat: { echecs: etat.echecs + 1, dernierEchec: maintenant, bloqueJusqua: etat.bloqueJusqua } };
}

type ContexteRequete = ContexteDeuxFacteurs & {
  path?: string;
  body?: Record<string, unknown>;
  context: ContexteDeuxFacteurs["context"] & { adapter: unknown };
};

/** Plugin Better Auth : au plus 3 e-mails de lien ou de code en 10 minutes par adresse. */
export const envoisEmailEnerlia = (options: OptionsEnvoisEmail = {}) => {
  const champParChemin = new Map(
    [...ROUTES_ENVOI_EMAIL, ...(options.routesSupplementaires ?? [])].map((r) => [r.chemin, r.champ]),
  );
  let stockageParDefaut: StockageTentatives | null = null;
  const stockage = (ctx: ContexteRequete): StockageTentatives => {
    if (options.stockage) return options.stockage;
    stockageParDefaut ??= stockageBase(ctx.context.adapter);
    return stockageParDefaut;
  };

  const cleDe = async (ctx: ContexteRequete): Promise<string | null> => {
    if (!ctx.path) return null;
    if (ctx.path === CHEMIN_CODE_2FA) {
      const userId = await utilisateurEn2fa(ctx);
      return userId ? cleEnvoi2fa(userId) : null;
    }
    const champ = champParChemin.get(ctx.path);
    const email = champ ? ctx.body?.[champ] : undefined;
    return typeof email === "string" && email.trim() ? cleEnvoiEmail(email) : null;
  };

  return {
    id: "enerlia-envois-email",
    hooks: {
      before: [
        {
          matcher: (ctx: { path?: string }) => !!ctx.path && (ctx.path === CHEMIN_CODE_2FA || champParChemin.has(ctx.path)),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            const cle = await cleDe(c);
            if (!cle) return;
            const decision = compterDemande(await stockage(c).lire(cle), Date.now(), options);
            if (decision.accepte) {
              await stockage(c).ecrire(cle, decision.etat);
              return;
            }
            throw new APIError(
              "TOO_MANY_REQUESTS",
              { message: MESSAGE_TROP_DE_DEMANDES, code: "TROP_DE_DEMANDES_EMAIL" },
              { "Retry-After": String(Math.max(1, Math.ceil(decision.attenteMs / 1000))) },
            );
          }),
        },
      ],
    },
    ...(options.stockage ? {} : { schema: SCHEMA_TENTATIVE }),
  } satisfies BetterAuthPlugin;
};
