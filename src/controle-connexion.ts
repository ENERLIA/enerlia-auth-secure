import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { estErreurApi } from "./erreurs";
import { type OptionsMotDePasse, verifierMotDePasse } from "./mot-de-passe";

/**
 * Contrôle des mots de passe existants à la connexion.
 *
 * Les règles de `motDePasseEnerlia` ne s'appliquent qu'au choix d'un mot de
 * passe : un mot de passe enregistré avant elles (trop court, devenu public
 * dans une fuite…) reste utilisable. Ce plugin le contrôle à chaque connexion
 * réussie, quand on le connaît en clair, et transmet le résultat à
 * l'application, qui impose alors le changement (drapeau, gardes serveur,
 * écran dédié). Rien n'est conservé : seul le résultat `conforme` sort.
 *
 * Il déconnecte aussi, une seule fois, chaque utilisateur dont le mot de passe
 * n'a encore jamais été contrôlé : à la lecture de la session ou du jeton
 * Convex, ses sessions sont supprimées. Sa prochaine connexion déclenche le
 * contrôle.
 *
 * La connexion n'est jamais bloquée par le contrôle lui-même : une erreur ou
 * un service de fuites injoignable laisse passer (liste locale appliquée).
 */

export type ResultatControle = {
  /** Identifiant Better Auth de l'utilisateur. */
  userId: string;
  /** Vrai si le mot de passe respecte les règles Enerlia. */
  conforme: boolean;
};

export type OptionsControleConnexion = Pick<
  OptionsMotDePasse,
  "nomApplication" | "longueurMin" | "longueurMax" | "motsInterdits"
> & {
  /** Enregistre le résultat d'un contrôle (connexion ou nouveau mot de passe). */
  enregistrer: (resultat: ResultatControle) => Promise<void>;
  /**
   * Vrai si le mot de passe de l'utilisateur a déjà été contrôlé. Sans valeur,
   * aucune session n'est coupée.
   */
  estControle?: (userId: string) => Promise<boolean>;
  /** Vérifier les fuites connues avec Pwned Passwords. Vrai par défaut. */
  verifierFuites?: boolean;
  /** Délai maximal de réponse du service de fuites, en millisecondes. 3 secondes par défaut. */
  delaiFuitesMs?: number;
};

const CHEMINS_CONNEXION = new Set(["/sign-in/email"]);
/** Routes où un utilisateur connecté choisit un nouveau mot de passe, et champ du corps concerné. */
const CHEMINS_NOUVEAU_MOT_DE_PASSE = new Map([
  ["/change-password", "newPassword"],
  ["/set-password", "newPassword"],
]);
/** Lecture de la session et du jeton Convex (@convex-dev/better-auth). */
const CHEMINS_SESSION = new Set(["/get-session", "/convex/token"]);

const PWNED_URL = "https://api.pwnedpasswords.com/range/";

/**
 * Vrai si le mot de passe figure dans une fuite connue (Pwned Passwords,
 * k-anonymat : seuls les 5 premiers caractères de l'empreinte SHA-1 sont
 * envoyés). Si le service ne répond pas à temps, la réponse est « non ».
 */
export async function estMotDePasseCompromis(motDePasse: string, delaiMs = 3000): Promise<boolean> {
  try {
    const empreinte = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(motDePasse.normalize("NFC")));
    const hash = Array.from(new Uint8Array(empreinte), (o) => o.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
    let minuteur: ReturnType<typeof setTimeout> | undefined;
    const delai = new Promise<null>((resoudre) => {
      minuteur = setTimeout(() => resoudre(null), delaiMs);
    });
    const requete = fetch(`${PWNED_URL}${hash.slice(0, 5)}`, { headers: { "Add-Padding": "true" } }).then(
      (r) => (r.ok ? r.text() : null),
    );
    const corps = await Promise.race([requete, delai]).finally(() => clearTimeout(minuteur));
    if (!corps) return false;
    const suffixe = hash.slice(5);
    return corps.split("\n").some((ligne) => {
      const [candidat, nombre] = ligne.trim().split(":");
      return candidat === suffixe && Number(nombre) > 0;
    });
  } catch {
    return false;
  }
}

type Utilisateur = { id?: string; email?: string; name?: string };

type ContexteRequete = {
  path?: string;
  body?: Record<string, unknown>;
  context: {
    appName?: string;
    returned?: unknown;
    newSession?: { user?: Utilisateur } | null;
    session?: unknown;
    internalAdapter: {
      findUserByEmail(email: string): Promise<{ user?: Utilisateur } | null>;
      deleteUserSessions(userId: string): Promise<void>;
    };
  };
};

async function utilisateurConnecte(ctx: ContexteRequete): Promise<Utilisateur | null> {
  try {
    return (await getSessionFromCtx(ctx as never))?.user ?? null;
  } catch {
    return null;
  }
}

/** Plugin Better Auth : contrôle à la connexion des mots de passe déjà enregistrés. */
export const controleConnexionEnerlia = (options: OptionsControleConnexion) => {
  const conforme = async (motDePasse: string, utilisateur: Utilisateur, appName?: string) => {
    const refus = verifierMotDePasse(
      motDePasse,
      { email: utilisateur.email, nom: utilisateur.name, application: options.nomApplication ?? appName },
      options,
    );
    if (refus) return false;
    if (options.verifierFuites === false) return true;
    return !(await estMotDePasseCompromis(motDePasse, options.delaiFuitesMs));
  };

  const controler = async (c: ContexteRequete, motDePasse: unknown, utilisateur: Utilisateur | null) => {
    if (typeof motDePasse !== "string" || !utilisateur?.id) return;
    try {
      await options.enregistrer({ userId: utilisateur.id, conforme: await conforme(motDePasse, utilisateur, c.context.appName) });
    } catch {
      // Le contrôle ne doit jamais faire échouer une connexion ou un changement de mot de passe.
    }
  };

  return {
    id: "enerlia-controle-connexion",
    hooks: {
      before: [
        {
          matcher: (ctx: { path?: string }) => !!options.estControle && !!ctx.path && CHEMINS_SESSION.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            const utilisateur = await utilisateurConnecte(c);
            if (!utilisateur?.id || !options.estControle) return;
            let controle = true;
            try {
              controle = await options.estControle(utilisateur.id);
            } catch {
              return;
            }
            if (controle) return;
            // Jamais contrôlé : on ferme ses sessions, la route répond alors « non connecté ».
            await c.context.internalAdapter.deleteUserSessions(utilisateur.id);
            c.context.session = null;
          }),
        },
      ],
      after: [
        {
          matcher: (ctx: { path?: string }) => !!ctx.path && CHEMINS_CONNEXION.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            // Échec : mauvais mot de passe, compte bloqué… rien à contrôler.
            if (estErreurApi(c.context.returned)) return;
            const email = c.body?.email;
            // Avec la double authentification, la session n'existe pas encore : on retrouve le compte par l'e-mail.
            const utilisateur =
              c.context.newSession?.user ??
              (typeof email === "string" ? ((await c.context.internalAdapter.findUserByEmail(email).catch(() => null))?.user ?? null) : null);
            await controler(c, c.body?.password, utilisateur);
          }),
        },
        {
          matcher: (ctx: { path?: string }) => !!ctx.path && CHEMINS_NOUVEAU_MOT_DE_PASSE.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx as unknown as ContexteRequete;
            if (estErreurApi(c.context.returned) || !c.path) return;
            const champ = CHEMINS_NOUVEAU_MOT_DE_PASSE.get(c.path) ?? "newPassword";
            await controler(c, c.body?.[champ], await utilisateurConnecte(c));
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
};
