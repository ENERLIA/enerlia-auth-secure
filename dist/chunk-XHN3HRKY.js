// src/session.ts
var HEURE_S = 60 * 60;
var SESSION_INACTIVITE_S = 48 * HEURE_S;
var SESSION_PROLONGATION_S = HEURE_S;
var SESSION_DUREE_MAX_MS = 7 * 24 * HEURE_S * 1e3;
var sessionEnerlia = {
  expiresIn: SESSION_INACTIVITE_S,
  updateAge: SESSION_PROLONGATION_S
};
function enDate(valeur) {
  if (valeur instanceof Date) return Number.isNaN(valeur.getTime()) ? null : valeur;
  if (typeof valeur === "string" || typeof valeur === "number") {
    const date = new Date(valeur);
    return Number.isNaN(date.getTime()) ? null : date;
  }
  return null;
}
function plafonnerExpiration(expiresAt, createdAt, maintenant = Date.now(), dureeMaxMs = SESSION_DUREE_MAX_MS) {
  const demandee = enDate(expiresAt);
  if (!demandee) return void 0;
  const limite = createdAt.getTime() + dureeMaxMs;
  if (limite <= maintenant) return false;
  if (demandee.getTime() <= limite) return void 0;
  return { data: { expiresAt: new Date(limite) } };
}
function creerLimiteDureeSession(dureeMaxMs = SESSION_DUREE_MAX_MS) {
  return async function limiterDureeSession2(data, context) {
    if (data.expiresAt === void 0) return void 0;
    const session = context?.context?.session?.session;
    const createdAt = enDate(session?.createdAt);
    if (!createdAt) return void 0;
    return plafonnerExpiration(data.expiresAt, createdAt, Date.now(), dureeMaxMs);
  };
}
var limiterDureeSession = creerLimiteDureeSession();
var dureeSessionEnerlia = (options = {}) => {
  const before = options.dureeMaxMs === void 0 ? limiterDureeSession : creerLimiteDureeSession(options.dureeMaxMs);
  return {
    id: "enerlia-duree-session",
    init: () => ({
      options: {
        databaseHooks: {
          session: { update: { before } }
        }
      }
    })
  };
};

export {
  SESSION_INACTIVITE_S,
  SESSION_PROLONGATION_S,
  SESSION_DUREE_MAX_MS,
  sessionEnerlia,
  plafonnerExpiration,
  creerLimiteDureeSession,
  limiterDureeSession,
  dureeSessionEnerlia
};
