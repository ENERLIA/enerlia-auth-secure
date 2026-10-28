import {
  MESSAGES_MOT_DE_PASSE,
  MOTS_DE_PASSE_COURANTS,
  ROUTES_MOT_DE_PASSE,
  estMotDePasseCourant,
  fragmentsPersonnels,
  motDePasseEnerlia,
  verifierMotDePasse
} from "./chunk-XX2VXDSU.js";
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
  MODELE_TENTATIVE,
  apresEchec,
  cle2fa,
  cleMotDePasse,
  delaiAvantEssai,
  refusAvantEssai,
  stockageMemoire,
  tentativesEnerlia
} from "./chunk-UFMUNCGM.js";
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
  MODELE_TENTATIVE,
  MOTS_DE_PASSE_COURANTS,
  ROUTES_MOT_DE_PASSE,
  SESSION_DUREE_MAX_MS,
  SESSION_INACTIVITE_S,
  SESSION_PROLONGATION_S,
  apresEchec,
  cle2fa,
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
