import { OptionsDureeSession } from './session.js';
export { SESSION_DUREE_MAX_MS, SESSION_INACTIVITE_S, SESSION_PROLONGATION_S, creerLimiteDureeSession, dureeSessionEnerlia, limiterDureeSession, plafonnerExpiration, sessionEnerlia } from './session.js';
import { OptionsTentatives } from './tentatives.js';
export { MESSAGE_COMPTE_BLOQUE, MESSAGE_DELAI, apresEchec, cle2fa, cleMotDePasse, delaiAvantEssai, refusAvantEssai, tentativesEnerlia } from './tentatives.js';
import { OptionsMotDePasse } from './mot-de-passe.js';
export { CodeRefusMotDePasse, MESSAGES_MOT_DE_PASSE, ROUTES_MOT_DE_PASSE, RouteMotDePasse, fragmentsPersonnels, motDePasseEnerlia, verifierMotDePasse } from './mot-de-passe.js';
import { OptionsEnvoisEmail } from './envois-email.js';
export { MESSAGE_TROP_DE_DEMANDES, ROUTES_ENVOI_EMAIL, RouteEnvoiEmail, cleEnvoi2fa, cleEnvoiEmail, compterDemande, envoisEmailEnerlia } from './envois-email.js';
import { BetterAuthPlugin } from 'better-auth';
export { E as EtatTentatives, M as MODELE_TENTATIVE, S as StockageTentatives, s as stockageMemoire } from './stockage-Cl_cWT5_.js';
import 'better-call';

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
declare function securiteEnerlia(options?: OptionsSecuriteEnerlia): BetterAuthPlugin[];

export { MOTS_DE_PASSE_COURANTS, OptionsDureeSession, OptionsEnvoisEmail, OptionsMotDePasse, type OptionsSecuriteEnerlia, OptionsTentatives, estMotDePasseCourant, securiteEnerlia };
