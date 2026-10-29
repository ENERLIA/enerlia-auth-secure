import * as better_call from 'better-call';

/**
 * Règles de mot de passe du référentiel Enerlia « Sécurité des comptes et des
 * connexions » v2.3, section 1 :
 * - 14 à 128 caractères, sans règle de composition imposée ;
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
type RouteMotDePasse = {
    /** Chemin Better Auth, par exemple `/invitation/activate-password`. */
    chemin: string;
    /** Champ du corps qui contient le nouveau mot de passe. */
    champ: string;
};
type OptionsMotDePasse = {
    /** Nom de l'application, refusé dans le mot de passe. Par défaut : `appName` de Better Auth. */
    nomApplication?: string;
    /** Longueur minimale, en caractères. 14 par défaut. */
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
declare const ROUTES_MOT_DE_PASSE: RouteMotDePasse[];
declare const MESSAGES_MOT_DE_PASSE: {
    readonly MOT_DE_PASSE_TROP_COURT: (min: number) => string;
    readonly MOT_DE_PASSE_TROP_LONG: (max: number) => string;
    readonly MOT_DE_PASSE_EMOJI: "Le mot de passe ne peut pas contenir d'émoji.";
    readonly MOT_DE_PASSE_COURANT: "Ce mot de passe est trop courant. Choisissez-en un autre.";
    readonly MOT_DE_PASSE_PERSONNEL: "Le mot de passe ne doit contenir ni votre adresse e-mail, ni votre nom, ni le nom de l'application.";
    readonly MOT_DE_PASSE_COMPROMIS: "Ce mot de passe figure dans une fuite de données connue. Choisissez-en un autre.";
};
/** Fragments personnels de 4 caractères ou plus à refuser dans le mot de passe. */
declare function fragmentsPersonnels(infos: {
    email?: string;
    nom?: string;
    application?: string;
}): string[];
type CodeRefusMotDePasse = Exclude<keyof typeof MESSAGES_MOT_DE_PASSE, "MOT_DE_PASSE_COMPROMIS">;
/** Contrôles locaux. Renvoie le code du premier refus, ou `null` si le mot de passe convient. */
declare function verifierMotDePasse(motDePasse: string, infos?: {
    email?: string;
    nom?: string;
    application?: string;
}, options?: Pick<OptionsMotDePasse, "longueurMin" | "longueurMax" | "motsInterdits">): CodeRefusMotDePasse | null;
type MotDePasseContexte = {
    hash: (motDePasse: string) => Promise<string>;
    verify: (donnees: {
        hash: string;
        password: string;
    }) => Promise<boolean>;
    [cle: string]: unknown;
};
/** Plugin Better Auth : règles de mot de passe Enerlia et contrôle des fuites connues. */
declare const motDePasseEnerlia: (options?: OptionsMotDePasse) => {
    id: "enerlia-mot-de-passe";
    init(contexte: {
        password: MotDePasseContexte;
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
};

export { type CodeRefusMotDePasse, MESSAGES_MOT_DE_PASSE, type OptionsMotDePasse, ROUTES_MOT_DE_PASSE, type RouteMotDePasse, fragmentsPersonnels, motDePasseEnerlia, verifierMotDePasse };
