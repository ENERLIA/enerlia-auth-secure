import * as better_call from 'better-call';
import { OptionsMotDePasse } from './mot-de-passe.js';

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
type ResultatControle = {
    /** Identifiant Better Auth de l'utilisateur. */
    userId: string;
    /** Vrai si le mot de passe respecte les règles Enerlia. */
    conforme: boolean;
};
type OptionsControleConnexion = Pick<OptionsMotDePasse, "nomApplication" | "longueurMin" | "longueurMax" | "motsInterdits"> & {
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
/**
 * Vrai si le mot de passe figure dans une fuite connue (Pwned Passwords,
 * k-anonymat : seuls les 5 premiers caractères de l'empreinte SHA-1 sont
 * envoyés). Si le service ne répond pas à temps, la réponse est « non ».
 */
declare function estMotDePasseCompromis(motDePasse: string, delaiMs?: number): Promise<boolean>;
/** Plugin Better Auth : contrôle à la connexion des mots de passe déjà enregistrés. */
declare const controleConnexionEnerlia: (options: OptionsControleConnexion) => {
    id: "enerlia-controle-connexion";
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

export { type OptionsControleConnexion, type ResultatControle, controleConnexionEnerlia, estMotDePasseCompromis };
