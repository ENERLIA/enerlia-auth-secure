import type { BetterAuthPlugin } from "better-auth";

/**
 * Durée des sessions selon le référentiel Enerlia « Sécurité des comptes et des
 * connexions » v2.3, section 5 :
 * - la session expire après 48 h sans activité ;
 * - elle dure au plus 7 jours après la connexion, même si l'utilisateur reste
 *   actif. Il doit alors se reconnecter.
 *
 * Better Auth applique la première règle avec `session.expiresIn` : chaque
 * requête prolonge la session, au plus une fois par `session.updateAge`. Il
 * n'a pas de durée maximale : sans plafond, une session utilisée chaque jour
 * ne s'arrête jamais. Le plugin `dureeSessionEnerlia` plafonne chaque
 * prolongation à la connexion + 7 jours, puis refuse la prolongation quand ce
 * délai est atteint : Better Auth ferme alors la session.
 */
const HEURE_S = 60 * 60;

/** Expiration après 48 h sans activité (`session.expiresIn`, en secondes). */
export const SESSION_INACTIVITE_S = 48 * HEURE_S;

/** Prolongation au plus une fois par heure d'activité (`session.updateAge`, en secondes). */
export const SESSION_PROLONGATION_S = HEURE_S;

/** Durée maximale d'une session après la connexion, en millisecondes. */
export const SESSION_DUREE_MAX_MS = 7 * 24 * HEURE_S * 1000;

/** Réglages à placer dans `session` de la configuration Better Auth. */
export const sessionEnerlia = {
  expiresIn: SESSION_INACTIVITE_S,
  updateAge: SESSION_PROLONGATION_S,
} as const;

function enDate(valeur: unknown): Date | null {
  if (valeur instanceof Date) return Number.isNaN(valeur.getTime()) ? null : valeur;
  if (typeof valeur === "string" || typeof valeur === "number") {
    const date = new Date(valeur);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  return null;
}

/**
 * Plafonne une nouvelle date d'expiration à la connexion + durée maximale.
 * Renvoie `false` quand la limite est atteinte (Better Auth annule alors la
 * prolongation et ferme la session), `undefined` quand rien ne change.
 */
export function plafonnerExpiration(
  expiresAt: unknown,
  createdAt: Date,
  maintenant: number = Date.now(),
  dureeMaxMs: number = SESSION_DUREE_MAX_MS,
): false | { data: { expiresAt: Date } } | undefined {
  const demandee = enDate(expiresAt);
  if (!demandee) return undefined;
  const limite = createdAt.getTime() + dureeMaxMs;
  if (limite <= maintenant) return false;
  if (demandee.getTime() <= limite) return undefined;
  return { data: { expiresAt: new Date(limite) } };
}

type ContexteSession = {
  context?: { session?: { session?: { createdAt?: unknown } } | null };
} | null;

/**
 * Point d'accroche `databaseHooks.session.update.before`. Avant de prolonger
 * une session, Better Auth la place dans le contexte de la requête
 * (`context.session`) : on y lit sa date de connexion.
 */
export function creerLimiteDureeSession(dureeMaxMs: number = SESSION_DUREE_MAX_MS) {
  return async function limiterDureeSession(
    data: { expiresAt?: unknown },
    context: unknown,
  ): Promise<false | { data: { expiresAt: Date } } | undefined> {
    if (data.expiresAt === undefined) return undefined;
    const session = (context as ContexteSession)?.context?.session?.session;
    const createdAt = enDate(session?.createdAt);
    if (!createdAt) return undefined;
    return plafonnerExpiration(data.expiresAt, createdAt, Date.now(), dureeMaxMs);
  };
}

export const limiterDureeSession = creerLimiteDureeSession();

export type OptionsDureeSession = {
  /** Durée maximale après la connexion, en millisecondes. 7 jours par défaut. */
  dureeMaxMs?: number;
};

/** Plugin Better Auth qui limite chaque session à 7 jours après la connexion. */
export const dureeSessionEnerlia = (options: OptionsDureeSession = {}) => {
  const before = options.dureeMaxMs === undefined ? limiterDureeSession : creerLimiteDureeSession(options.dureeMaxMs);
  return {
    id: "enerlia-duree-session",
    init: () => ({
      options: {
        databaseHooks: {
          session: { update: { before } },
        },
      },
    }),
  } satisfies BetterAuthPlugin;
};
