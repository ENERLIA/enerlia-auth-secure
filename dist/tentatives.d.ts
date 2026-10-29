import * as better_call from 'better-call';
import { S as StockageTentatives, E as EtatTentatives } from './stockage-Cl_cWT5_.js';
export { M as MODELE_TENTATIVE, s as stockageMemoire } from './stockage-Cl_cWT5_.js';

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
type OptionsTentatives = {
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
declare const MESSAGE_COMPTE_BLOQUE = "Trop de tentatives. R\u00E9essayez dans 15 minutes ou r\u00E9initialisez votre mot de passe.";
declare const MESSAGE_DELAI = "Trop de tentatives rapproch\u00E9es. Patientez quelques secondes avant de r\u00E9essayer.";
declare function cleMotDePasse(email: string): string;
declare function cle2fa(userId: string): string;
/** Délai à respecter avant l'essai suivant, selon le nombre d'échecs consécutifs. */
declare function delaiAvantEssai(echecs: number, options?: Pick<OptionsTentatives, "echecsAvantDelai" | "delaiInitialMs" | "delaiMaxMs">): number;
/** Nouvel état après un échec. */
declare function apresEchec(etat: EtatTentatives | null, maintenant: number, options?: Pick<OptionsTentatives, "echecsAvantBlocage" | "dureeBlocageMs" | "oubliApresMs">): EtatTentatives;
/** Refus à opposer avant un essai, ou `null` si l'essai est autorisé. */
declare function refusAvantEssai(etat: EtatTentatives | null, maintenant: number, options?: Omit<OptionsTentatives, "stockage">): {
    raison: "bloque" | "delai";
    attenteMs: number;
} | null;
/** Plugin Better Auth : délai croissant et blocage temporaire par compte. */
declare const tentativesEnerlia: (options?: OptionsTentatives) => {
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
};

export { EtatTentatives, MESSAGE_COMPTE_BLOQUE, MESSAGE_DELAI, type OptionsTentatives, StockageTentatives, apresEchec, cle2fa, cleMotDePasse, delaiAvantEssai, refusAvantEssai, tentativesEnerlia };
