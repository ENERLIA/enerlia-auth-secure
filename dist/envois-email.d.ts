import * as better_call from 'better-call';
import { S as StockageTentatives, E as EtatTentatives } from './stockage-Cl_cWT5_.js';

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
type RouteEnvoiEmail = {
    /** Chemin Better Auth, par exemple `/invitation/resend`. */
    chemin: string;
    /** Champ du corps qui contient l'adresse e-mail destinataire. */
    champ: string;
};
type OptionsEnvoisEmail = {
    /** Stockage des compteurs. Sans valeur : la table `enerliaTentative` de la base Better Auth. */
    stockage?: StockageTentatives;
    /** Demandes autorisées par adresse sur la fenêtre. 3 par défaut. */
    maxDemandes?: number;
    /** Fenêtre de comptage, en millisecondes. 10 minutes par défaut. */
    fenetreMs?: number;
    /** Routes propres à l'application qui envoient un e-mail (renvoi d'invitation…). */
    routesSupplementaires?: RouteEnvoiEmail[];
};
declare const ROUTES_ENVOI_EMAIL: RouteEnvoiEmail[];
declare const MESSAGE_TROP_DE_DEMANDES = "Trop de demandes pour cette adresse e-mail. R\u00E9essayez dans quelques minutes.";
declare function cleEnvoiEmail(email: string): string;
declare function cleEnvoi2fa(userId: string): string;
/**
 * Compte une demande d'envoi sur une fenêtre fixe. Renvoie le nouvel état à
 * enregistrer si la demande est acceptée, ou le temps d'attente si elle est refusée.
 */
declare function compterDemande(etat: EtatTentatives | null, maintenant: number, options?: Pick<OptionsEnvoisEmail, "maxDemandes" | "fenetreMs">): {
    accepte: true;
    etat: EtatTentatives;
} | {
    accepte: false;
    attenteMs: number;
};
/** Plugin Better Auth : au plus 3 e-mails de lien ou de code en 10 minutes par adresse. */
declare const envoisEmailEnerlia: (options?: OptionsEnvoisEmail) => {
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
};

export { MESSAGE_TROP_DE_DEMANDES, type OptionsEnvoisEmail, ROUTES_ENVOI_EMAIL, type RouteEnvoiEmail, cleEnvoi2fa, cleEnvoiEmail, compterDemande, envoisEmailEnerlia };
