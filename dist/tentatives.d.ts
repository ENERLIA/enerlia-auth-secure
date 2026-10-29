import * as better_call from 'better-call';

/**
 * Protection contre les attaques par force brute, selon le référentiel Enerlia
 * « Sécurité des comptes et des connexions » v2.0, section 3 :
 * - délai croissant après chaque échec pour un même compte, à partir du 3e ;
 * - blocage temporaire du compte après 10 échecs consécutifs (15 min), levé
 *   aussi par une réinitialisation ou un changement du mot de passe ;
 * - même protection pour les codes 2FA (TOTP, code par e-mail, codes de secours) ;
 * - le blocage s'applique au compte visé uniquement : un collègue qui partage
 *   la même connexion se connecte normalement ;
 * - en complément, une limite par adresse IP qui ne compte que les échecs, avec
 *   un seuil élevé (50 échecs en 15 minutes), contre un attaquant qui essaie de
 *   nombreux comptes depuis la même adresse. La limite `rateLimit` de Better
 *   Auth, qui compte toutes les requêtes, doit rester large (voir le README).
 *
 * Les essais sur une adresse inconnue sont comptés et traités comme les autres :
 * la réponse ne révèle jamais si un compte existe.
 */
type EtatTentatives = {
    /** Nombre d'échecs consécutifs. */
    echecs: number;
    /** Date du dernier échec (ms depuis l'époque Unix). */
    dernierEchec: number;
    /**
     * Compte : fin du blocage (ms depuis l'époque Unix), 0 s'il n'est pas bloqué.
     * Adresse IP : fin de la fenêtre de comptage en cours.
     */
    bloqueJusqua: number;
};
/** Où ranger les compteurs. Par défaut : une table de la base Better Auth. */
interface StockageTentatives {
    lire(cle: string): Promise<EtatTentatives | null>;
    ecrire(cle: string, etat: EtatTentatives): Promise<void>;
    effacer(cle: string): Promise<void>;
}
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
    /**
     * Échecs tolérés par adresse IP sur la fenêtre `fenetreIpMs`, tous comptes
     * confondus. 50 par défaut ; `false` désactive cette limite.
     */
    echecsParIp?: number | false;
    /** Fenêtre de comptage des échecs par adresse IP, en millisecondes. 15 minutes par défaut. */
    fenetreIpMs?: number;
    /** Routes de connexion par mot de passe dont le corps contient `email`. */
    cheminsMotDePasse?: string[];
    /** Routes de vérification d'un code 2FA. */
    chemins2fa?: string[];
};
declare const MODELE_TENTATIVE = "enerliaTentative";
declare const MESSAGE_COMPTE_BLOQUE = "Trop de tentatives. R\u00E9essayez dans 15 minutes ou r\u00E9initialisez votre mot de passe.";
declare const MESSAGE_DELAI = "Trop de tentatives rapproch\u00E9es. Patientez quelques secondes avant de r\u00E9essayer.";
declare const MESSAGE_RESEAU_BLOQUE = "Trop de tentatives \u00E9chou\u00E9es depuis votre r\u00E9seau. R\u00E9essayez dans quelques minutes.";
/** Stockage en mémoire, pour les tests et le développement local. */
declare function stockageMemoire(): StockageTentatives & {
    donnees: Map<string, EtatTentatives>;
};
declare function cleMotDePasse(email: string): string;
declare function cle2fa(userId: string): string;
declare function cleIp(ip: string): string;
/** Nouvel état d'une adresse IP après un échec : compteur sur une fenêtre fixe. */
declare function apresEchecIp(etat: EtatTentatives | null, maintenant: number, fenetreMs?: number): EtatTentatives;
/** Temps d'attente imposé à une adresse IP, ou 0 si elle peut encore essayer. */
declare function attenteIp(etat: EtatTentatives | null, maintenant: number, seuil?: number): number;
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
        enerliaTentative: {
            fields: {
                cle: {
                    type: "string";
                    required: true;
                    unique: true;
                };
                echecs: {
                    type: "number";
                    required: true;
                };
                dernierEchec: {
                    type: "number";
                    required: true;
                };
                bloqueJusqua: {
                    type: "number";
                    required: true;
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

export { type EtatTentatives, MESSAGE_COMPTE_BLOQUE, MESSAGE_DELAI, MESSAGE_RESEAU_BLOQUE, MODELE_TENTATIVE, type OptionsTentatives, type StockageTentatives, apresEchec, apresEchecIp, attenteIp, cle2fa, cleIp, cleMotDePasse, delaiAvantEssai, refusAvantEssai, stockageMemoire, tentativesEnerlia };
