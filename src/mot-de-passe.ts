import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { haveIBeenPwned } from "better-auth/plugins/haveibeenpwned";
import { estErreurApi, messageErreur } from "./erreurs";
import { MOTS_DE_PASSE_COURANTS, estMotDePasseCourant } from "./mots-de-passe-courants";

/**
 * Règles de mot de passe du référentiel Enerlia « Sécurité des comptes et des
 * connexions » v2.0, section 1 :
 * - 12 à 128 caractères, sans règle de composition imposée ;
 * - émojis refusés, caractères accentués normalisés (Unicode NFC) avant le hachage ;
 * - refus des mots de passe courants, de ceux qui contiennent l'e-mail, le nom
 *   de l'utilisateur ou le nom de l'application ;
 * - refus des mots de passe présents dans une fuite connue, avec le plugin
 *   officiel `haveIBeenPwned` de Better Auth (k-anonymat) ; si le service ne
 *   répond pas, la liste locale prend le relais au lieu de bloquer l'utilisateur.
 *
 * Les contrôles s'appliquent quand un mot de passe est choisi. Ils ne touchent
 * pas les mots de passe déjà enregistrés.
 */

export type RouteMotDePasse = {
  /** Chemin Better Auth, par exemple `/invitation/activate-password`. */
  chemin: string;
  /** Champ du corps qui contient le nouveau mot de passe. */
  champ: string;
};

export type OptionsMotDePasse = {
  /** Nom de l'application, refusé dans le mot de passe. Par défaut : `appName` de Better Auth. */
  nomApplication?: string;
  /** Longueur minimale, en caractères. 12 par défaut. */
  longueurMin?: number;
  /** Longueur maximale, en caractères. 128 par défaut. */
  longueurMax?: number;
  /** Vérifier les fuites connues avec Pwned Passwords. Vrai par défaut. */
  verifierFuites?: boolean;
  /** Routes propres à l'application où l'on choisit un mot de passe. */
  routesSupplementaires?: RouteMotDePasse[];
  /** Mots de passe courants supplémentaires à refuser. */
  motsInterdits?: string[];
};

export const ROUTES_MOT_DE_PASSE: RouteMotDePasse[] = [
  { chemin: "/sign-up/email", champ: "password" },
  { chemin: "/change-password", champ: "newPassword" },
  { chemin: "/set-password", champ: "newPassword" },
  { chemin: "/reset-password", champ: "newPassword" },
  { chemin: "/email-otp/reset-password", champ: "password" },
  { chemin: "/admin/create-user", champ: "password" },
  { chemin: "/admin/set-user-password", champ: "newPassword" },
];

export const MESSAGES_MOT_DE_PASSE = {
  MOT_DE_PASSE_TROP_COURT: (min: number) => `Le mot de passe doit contenir au moins ${min} caractères.`,
  MOT_DE_PASSE_TROP_LONG: (max: number) => `Le mot de passe doit contenir au plus ${max} caractères.`,
  MOT_DE_PASSE_EMOJI: "Le mot de passe ne peut pas contenir d'émoji.",
  MOT_DE_PASSE_COURANT: "Ce mot de passe est trop courant. Choisissez-en un autre.",
  MOT_DE_PASSE_PERSONNEL: "Le mot de passe ne doit contenir ni votre adresse e-mail, ni votre nom, ni le nom de l'application.",
  MOT_DE_PASSE_COMPROMIS:
    "Ce mot de passe figure dans une fuite de données connue. Choisissez-en un autre.",
} as const;

const EMOJI = /\p{Extended_Pictographic}|\p{Regional_Indicator}|\u{FE0F}/u;

/** Minuscules sans accents, pour comparer des mots sans tenir compte de la saisie. */
function simplifier(texte: string): string {
  return texte.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
}

/** Fragments personnels de 4 caractères ou plus à refuser dans le mot de passe. */
export function fragmentsPersonnels(infos: { email?: string; nom?: string; application?: string }): string[] {
  const fragments = new Set<string>();
  const ajouter = (texte?: string) => {
    if (!texte) return;
    const simple = simplifier(texte);
    for (const mot of simple.split(/[^\p{L}\p{N}]+/u)) if (mot.length >= 4) fragments.add(mot);
    const colle = simple.replace(/[^\p{L}\p{N}]+/gu, "");
    if (colle.length >= 4) fragments.add(colle);
  };
  if (infos.email) ajouter(infos.email.split("@")[0]);
  ajouter(infos.nom);
  ajouter(infos.application);
  return [...fragments];
}

export type CodeRefusMotDePasse = Exclude<keyof typeof MESSAGES_MOT_DE_PASSE, "MOT_DE_PASSE_COMPROMIS">;

/** Contrôles locaux. Renvoie le code du premier refus, ou `null` si le mot de passe convient. */
export function verifierMotDePasse(
  motDePasse: string,
  infos: { email?: string; nom?: string; application?: string } = {},
  options: Pick<OptionsMotDePasse, "longueurMin" | "longueurMax" | "motsInterdits"> = {},
): CodeRefusMotDePasse | null {
  const normalise = motDePasse.normalize("NFC");
  const longueur = [...normalise].length;
  if (longueur < (options.longueurMin ?? 12)) return "MOT_DE_PASSE_TROP_COURT";
  if (longueur > (options.longueurMax ?? 128)) return "MOT_DE_PASSE_TROP_LONG";
  if (EMOJI.test(normalise)) return "MOT_DE_PASSE_EMOJI";
  const liste = options.motsInterdits?.length
    ? [...MOTS_DE_PASSE_COURANTS, ...options.motsInterdits.map((m) => m.toLowerCase())]
    : MOTS_DE_PASSE_COURANTS;
  if (estMotDePasseCourant(normalise, liste)) return "MOT_DE_PASSE_COURANT";
  const simple = simplifier(normalise).replace(/\s+/g, "");
  if (fragmentsPersonnels(infos).some((fragment) => simple.includes(fragment))) return "MOT_DE_PASSE_PERSONNEL";
  return null;
}

type ContexteRequete = {
  path?: string;
  body?: Record<string, unknown>;
  query?: Record<string, unknown>;
  context: {
    appName?: string;
    internalAdapter: {
      findVerificationValue(identifier: string): Promise<{ value: string } | null>;
      findUserById(id: string): Promise<{ email?: string; name?: string } | null>;
    };
  };
};

async function personneConcernee(ctx: ContexteRequete): Promise<{ email?: string; nom?: string }> {
  const corps = ctx.body ?? {};
  const texte = (valeur: unknown) => (typeof valeur === "string" && valeur ? valeur : undefined);
  let email = texte(corps.email);
  let nom = texte(corps.name);
  const completer = (utilisateur?: { email?: string; name?: string } | null) => {
    email ??= texte(utilisateur?.email);
    nom ??= texte(utilisateur?.name);
  };
  try {
    if (typeof corps.userId === "string") completer(await ctx.context.internalAdapter.findUserById(corps.userId));
    const jeton = corps.token ?? ctx.query?.token;
    if (ctx.path === "/reset-password" && typeof jeton === "string" && jeton) {
      const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${jeton}`);
      if (verification?.value) completer(await ctx.context.internalAdapter.findUserById(verification.value));
    }
    if (!email || !nom) completer((await getSessionFromCtx(ctx as never))?.user);
  } catch {
    // Contrôle au mieux : sans e-mail ni nom, les autres règles s'appliquent quand même.
  }
  return { email, nom };
}

type MotDePasseContexte = {
  hash: (motDePasse: string) => Promise<string>;
  verify: (donnees: { hash: string; password: string }) => Promise<boolean>;
  [cle: string]: unknown;
};

/** Plugin Better Auth : règles de mot de passe Enerlia et contrôle des fuites connues. */
export const motDePasseEnerlia = (options: OptionsMotDePasse = {}) => {
  const routes = [...ROUTES_MOT_DE_PASSE, ...(options.routesSupplementaires ?? [])];
  const champParChemin = new Map(routes.map((r) => [r.chemin, r.champ]));
  const fuites = haveIBeenPwned({
    paths: routes.map((r) => r.chemin),
    customPasswordCompromisedMessage: MESSAGES_MOT_DE_PASSE.MOT_DE_PASSE_COMPROMIS,
  });

  return {
    id: "enerlia-mot-de-passe",
    init(contexte: { password: MotDePasseContexte; appName?: string }) {
      const original = contexte.password;
      // Le plugin officiel enveloppe la fonction de hachage pour interroger Pwned Passwords.
      const avecFuites =
        options.verifierFuites === false
          ? original
          : ((fuites.init(contexte as never) as { context: { password: MotDePasseContexte } }).context.password);
      return {
        context: {
          password: {
            ...original,
            async hash(motDePasse: string) {
              const normalise = motDePasse.normalize("NFC");
              try {
                return await avecFuites.hash(normalise);
              } catch (erreur) {
                // Service Pwned Passwords indisponible : la liste locale a déjà été appliquée.
                if (estErreurApi(erreur) && erreur.statusCode === 500 && messageErreur(erreur).startsWith("Failed to check password")) {
                  return original.hash(normalise);
                }
                throw erreur;
              }
            },
            async verify(donnees: { hash: string; password: string }) {
              const normalise = donnees.password.normalize("NFC");
              if (await original.verify({ ...donnees, password: normalise })) return true;
              // Mots de passe enregistrés avant la normalisation (saisis sous une autre forme Unicode).
              return normalise !== donnees.password && original.verify(donnees);
            },
          },
        },
      };
    },
    hooks: {
      before: [
        {
          matcher: (ctx: { path?: string }) => !!ctx.path && champParChemin.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            const champ = c.path ? champParChemin.get(c.path) : undefined;
            const motDePasse = champ ? c.body?.[champ] : undefined;
            if (typeof motDePasse !== "string") return;
            const personne = await personneConcernee(c);
            const refus = verifierMotDePasse(
              motDePasse,
              { ...personne, application: options.nomApplication ?? c.context.appName },
              options,
            );
            if (!refus) return;
            const message =
              refus === "MOT_DE_PASSE_TROP_COURT"
                ? MESSAGES_MOT_DE_PASSE.MOT_DE_PASSE_TROP_COURT(options.longueurMin ?? 12)
                : refus === "MOT_DE_PASSE_TROP_LONG"
                  ? MESSAGES_MOT_DE_PASSE.MOT_DE_PASSE_TROP_LONG(options.longueurMax ?? 128)
                  : MESSAGES_MOT_DE_PASSE[refus];
            throw new APIError("BAD_REQUEST", { message, code: refus });
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
};
