import * as better_call from 'better-call';
import { OptionsDureeSession } from './session.js';
export { SESSION_DUREE_MAX_MS, SESSION_INACTIVITE_S, SESSION_PROLONGATION_S, creerLimiteDureeSession, dureeSessionEnerlia, limiterDureeSession, plafonnerExpiration, sessionEnerlia } from './session.js';
import { OptionsTentatives } from './tentatives.js';
export { MESSAGE_COMPTE_BLOQUE, MESSAGE_DELAI, apresEchec, cle2fa, cleMotDePasse, delaiAvantEssai, refusAvantEssai, tentativesEnerlia } from './tentatives.js';
import { OptionsMotDePasse } from './mot-de-passe.js';
export { CodeRefusMotDePasse, MESSAGES_MOT_DE_PASSE, ROUTES_MOT_DE_PASSE, RouteMotDePasse, fragmentsPersonnels, motDePasseEnerlia, verifierMotDePasse } from './mot-de-passe.js';
import { OptionsEnvoisEmail } from './envois-email.js';
export { MESSAGE_TROP_DE_DEMANDES, ROUTES_ENVOI_EMAIL, RouteEnvoiEmail, cleEnvoi2fa, cleEnvoiEmail, compterDemande, envoisEmailEnerlia } from './envois-email.js';
export { E as EtatTentatives, M as MODELE_TENTATIVE, S as StockageTentatives, s as stockageMemoire } from './stockage-Cl_cWT5_.js';

/**
 * Mots de passe courants refusés même quand le service Pwned Passwords ne
 * répond pas. La liste vise les mots de passe de 12 caractères et plus (les
 * plus courts sont déjà refusés par la longueur) ; les suites et répétitions
 * sont détectées à part dans `estMotDePasseCourant`.
 */
declare const MOTS_DE_PASSE_COURANTS: readonly string[];
/** Vrai pour un mot de passe de la liste, une répétition ou une simple suite de clavier. */
declare function estMotDePasseCourant(motDePasse: string, liste?: readonly string[]): boolean;

type OptionsSecuriteEnerlia = {
    session?: OptionsDureeSession | false;
    tentatives?: OptionsTentatives | false;
    motDePasse?: OptionsMotDePasse | false;
    envoisEmail?: OptionsEnvoisEmail | false;
};
/**
 * Tous les plugins du référentiel Enerlia, à étaler dans `plugins` :
 * `plugins: [...securiteEnerlia({ ... }), twoFactor(), ...]`.
 * Penser aussi à `session: sessionEnerlia` dans la configuration Better Auth.
 */
declare function securiteEnerlia(options?: OptionsSecuriteEnerlia): ({
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
} | {
    schema?: {
        readonly enerliaTentative: {
            readonly fields: {
                readonly cle: {
                    readonly type: "string";
                    readonly required: true;
                    readonly unique: true;
                };
                readonly echecs: {
                    readonly type: "number";
                    readonly required: true;
                };
                readonly dernierEchec: {
                    readonly type: "number";
                    readonly required: true;
                };
                readonly bloqueJusqua: {
                    readonly type: "number";
                    readonly required: true;
                };
            };
        };
    } | undefined;
    id: "enerlia-tentatives";
    hooks: {
        before: {
            matcher: (ctx: {
                path?: string;
            }) => boolean;
            handler: better_call.Middleware<better_call.MiddlewareOptions, (inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<void>>;
        }[];
        after: {
            matcher: (ctx: {
                path?: string;
            }) => boolean;
            handler: better_call.Middleware<better_call.MiddlewareOptions, (inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<void>>;
        }[];
    };
} | {
    id: "enerlia-mot-de-passe";
    init(contexte: {
        password: {
            [cle: string]: unknown;
            hash: (motDePasse: string) => Promise<string>;
            verify: (donnees: {
                hash: string;
                password: string;
            }) => Promise<boolean>;
        };
        appName?: string;
    }): {
        context: {
            password: {
                hash(motDePasse: string): Promise<string>;
                verify(donnees: {
                    hash: string;
                    password: string;
                }): Promise<boolean>;
            };
        };
    };
    hooks: {
        before: {
            matcher: (ctx: {
                path?: string;
            }) => boolean;
            handler: better_call.Middleware<better_call.MiddlewareOptions, (inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<void>>;
        }[];
    };
} | {
    schema?: {
        readonly enerliaTentative: {
            readonly fields: {
                readonly cle: {
                    readonly type: "string";
                    readonly required: true;
                    readonly unique: true;
                };
                readonly echecs: {
                    readonly type: "number";
                    readonly required: true;
                };
                readonly dernierEchec: {
                    readonly type: "number";
                    readonly required: true;
                };
                readonly bloqueJusqua: {
                    readonly type: "number";
                    readonly required: true;
                };
            };
        };
    } | undefined;
    id: "enerlia-envois-email";
    hooks: {
        before: {
            matcher: (ctx: {
                path?: string;
            }) => boolean;
            handler: better_call.Middleware<better_call.MiddlewareOptions, (inputContext: better_call.MiddlewareInputContext<better_call.MiddlewareOptions>) => Promise<void>>;
        }[];
    };
})[];

export { MOTS_DE_PASSE_COURANTS, OptionsDureeSession, OptionsEnvoisEmail, OptionsMotDePasse, type OptionsSecuriteEnerlia, OptionsTentatives, estMotDePasseCourant, securiteEnerlia };
