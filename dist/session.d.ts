/** Expiration après 48 h sans activité (`session.expiresIn`, en secondes). */
declare const SESSION_INACTIVITE_S: number;
/** Prolongation au plus une fois par heure d'activité (`session.updateAge`, en secondes). */
declare const SESSION_PROLONGATION_S: number;
/** Durée maximale d'une session après la connexion, en millisecondes. */
declare const SESSION_DUREE_MAX_MS: number;
/** Réglages à placer dans `session` de la configuration Better Auth. */
declare const sessionEnerlia: {
    readonly expiresIn: number;
    readonly updateAge: number;
};
/**
 * Plafonne une nouvelle date d'expiration à la connexion + durée maximale.
 * Renvoie `false` quand la limite est atteinte (Better Auth annule alors la
 * prolongation et ferme la session), `undefined` quand rien ne change.
 */
declare function plafonnerExpiration(expiresAt: unknown, createdAt: Date, maintenant?: number, dureeMaxMs?: number): false | {
    data: {
        expiresAt: Date;
    };
} | undefined;
/**
 * Point d'accroche `databaseHooks.session.update.before`. Avant de prolonger
 * une session, Better Auth la place dans le contexte de la requête
 * (`context.session`) : on y lit sa date de connexion.
 */
declare function creerLimiteDureeSession(dureeMaxMs?: number): (data: {
    expiresAt?: unknown;
}, context: unknown) => Promise<false | {
    data: {
        expiresAt: Date;
    };
} | undefined>;
declare const limiterDureeSession: (data: {
    expiresAt?: unknown;
}, context: unknown) => Promise<false | {
    data: {
        expiresAt: Date;
    };
} | undefined>;
type OptionsDureeSession = {
    /** Durée maximale après la connexion, en millisecondes. 7 jours par défaut. */
    dureeMaxMs?: number;
};
/** Plugin Better Auth qui limite chaque session à 7 jours après la connexion. */
declare const dureeSessionEnerlia: (options?: OptionsDureeSession) => {
    id: "enerlia-duree-session";
    init: () => {
        options: {
            databaseHooks: {
                session: {
                    update: {
                        before: (data: {
                            expiresAt?: unknown;
                        }, context: unknown) => Promise<false | {
                            data: {
                                expiresAt: Date;
                            };
                        } | undefined>;
                    };
                };
            };
        };
    };
};

export { type OptionsDureeSession, SESSION_DUREE_MAX_MS, SESSION_INACTIVITE_S, SESSION_PROLONGATION_S, creerLimiteDureeSession, dureeSessionEnerlia, limiterDureeSession, plafonnerExpiration, sessionEnerlia };
