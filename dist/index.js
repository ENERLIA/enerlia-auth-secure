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
  MESSAGE_RESEAU_BLOQUE,
  MODELE_TENTATIVE,
  apresEchec,
  apresEchecIp,
  attenteIp,
  cle2fa,
  cleIp,
  cleMotDePasse,
  delaiAvantEssai,
  refusAvantEssai,
  stockageMemoire,
  tentativesEnerlia
} from "./chunk-GNK37D6D.js";
import "./chunk-NCGPCWYH.js";

// src/index.ts
function securiteEnerlia(options = {}) {
  return [
    ...options.session === false ? [] : [dureeSessionEnerlia(options.session)],
    ...options.tentatives === false ? [] : [tentativesEnerlia(options.tentatives)],
    ...options.motDePasse === false ? [] : [motDePasseEnerlia(options.motDePasse)]
  ];
}
export {
  MESSAGES_MOT_DE_PASSE,
  MESSAGE_COMPTE_BLOQUE,
  MESSAGE_DELAI,
  MESSAGE_RESEAU_BLOQUE,
  MODELE_TENTATIVE,
  MOTS_DE_PASSE_COURANTS,
  ROUTES_MOT_DE_PASSE,
  SESSION_DUREE_MAX_MS,
  SESSION_INACTIVITE_S,
  SESSION_PROLONGATION_S,
  apresEchec,
  apresEchecIp,
  attenteIp,
  cle2fa,
  cleIp,
  cleMotDePasse,
  creerLimiteDureeSession,
  delaiAvantEssai,
  dureeSessionEnerlia,
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
