import {
  controleConnexionEnerlia,
  estMotDePasseCompromis
} from "./chunk-D6S3V4WY.js";
import {
  MESSAGE_TROP_DE_DEMANDES,
  ROUTES_ENVOI_EMAIL,
  cleEnvoi2fa,
  cleEnvoiEmail,
  compterDemande,
  envoisEmailEnerlia
} from "./chunk-V3HRWTLY.js";
import {
  MESSAGES_MOT_DE_PASSE,
  MOTS_DE_PASSE_COURANTS,
  ROUTES_MOT_DE_PASSE,
  estMotDePasseCourant,
  fragmentsPersonnels,
  motDePasseEnerlia,
  verifierMotDePasse
} from "./chunk-H2NJ5EZK.js";
import {
  SESSION_DUREE_MAX_MS,
  SESSION_INACTIVITE_S,
  SESSION_PROLONGATION_S,
  creerLimiteDureeSession,
  dureeSessionEnerlia,
  limiterDureeSession,
  plafonnerExpiration,
  sessionEnerlia
} from "./chunk-XHN3HRKY.js";
import {
  MESSAGE_COMPTE_BLOQUE,
  MESSAGE_DELAI,
  apresEchec,
  cle2fa,
  cleMotDePasse,
  delaiAvantEssai,
  refusAvantEssai,
  tentativesEnerlia
} from "./chunk-4KH4FBSA.js";
import {
  MODELE_TENTATIVE,
  stockageMemoire
} from "./chunk-JFKTIXMC.js";
import "./chunk-NCGPCWYH.js";

// src/index.ts
function securiteEnerlia(options = {}) {
  return [
    ...options.session === false ? [] : [dureeSessionEnerlia(options.session)],
    ...options.tentatives === false ? [] : [tentativesEnerlia(options.tentatives)],
    ...options.motDePasse === false ? [] : [motDePasseEnerlia(options.motDePasse)],
    ...options.envoisEmail === false ? [] : [envoisEmailEnerlia(options.envoisEmail)]
  ];
}
export {
  MESSAGES_MOT_DE_PASSE,
  MESSAGE_COMPTE_BLOQUE,
  MESSAGE_DELAI,
  MESSAGE_TROP_DE_DEMANDES,
  MODELE_TENTATIVE,
  MOTS_DE_PASSE_COURANTS,
  ROUTES_ENVOI_EMAIL,
  ROUTES_MOT_DE_PASSE,
  SESSION_DUREE_MAX_MS,
  SESSION_INACTIVITE_S,
  SESSION_PROLONGATION_S,
  apresEchec,
  cle2fa,
  cleEnvoi2fa,
  cleEnvoiEmail,
  cleMotDePasse,
  compterDemande,
  controleConnexionEnerlia,
  creerLimiteDureeSession,
  delaiAvantEssai,
  dureeSessionEnerlia,
  envoisEmailEnerlia,
  estMotDePasseCompromis,
  estMotDePasseCourant,
  fragmentsPersonnels,
  limiterDureeSession,
  motDePasseEnerlia,
  plafonnerExpiration,
  refusAvantEssai,
  securiteEnerlia,
  sessionEnerlia,
  stockageMemoire,
  tentativesEnerlia,
  verifierMotDePasse
};
