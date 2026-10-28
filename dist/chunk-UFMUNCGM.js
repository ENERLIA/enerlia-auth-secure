import {
  codeErreur,
  estErreurApi
} from "./chunk-NCGPCWYH.js";

// src/tentatives.ts
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
var MODELE_TENTATIVE = "enerliaTentative";
var MESSAGE_COMPTE_BLOQUE = "Trop de tentatives. R\xE9essayez dans 15 minutes ou r\xE9initialisez votre mot de passe.";
var MESSAGE_DELAI = "Trop de tentatives rapproch\xE9es. Patientez quelques secondes avant de r\xE9essayer.";
var CHEMINS_MOT_DE_PASSE = ["/sign-in/email"];
var CHEMINS_2FA = ["/two-factor/verify-totp", "/two-factor/verify-otp", "/two-factor/verify-backup-code"];
var CHEMIN_LIEN_REINITIALISATION = "/reset-password";
var CHEMINS_REINITIALISATION_PAR_EMAIL = /* @__PURE__ */ new Set(["/email-otp/reset-password"]);
var CHEMINS_CHANGEMENT_CONNECTE = /* @__PURE__ */ new Set(["/change-password", "/set-password"]);
var CHEMIN_ADMIN = "/admin/set-user-password";
var ERREURS_NON_COMPTEES = /* @__PURE__ */ new Set(["INVALID_TWO_FACTOR_COOKIE"]);
function stockageMemoire() {
  const donnees = /* @__PURE__ */ new Map();
  return {
    donnees,
    async lire(cle) {
      const etat = donnees.get(cle);
      return etat ? { ...etat } : null;
    },
    async ecrire(cle, etat) {
      donnees.set(cle, { ...etat });
    },
    async effacer(cle) {
      donnees.delete(cle);
    }
  };
}
function stockageBase(adaptateur) {
  const ou = (cle) => [{ field: "cle", value: cle }];
  const lire = async (cle) => {
    const ligne = await adaptateur.findOne({ model: MODELE_TENTATIVE, where: ou(cle) });
    if (!ligne) return null;
    return {
      echecs: Number(ligne.echecs) || 0,
      dernierEchec: Number(ligne.dernierEchec) || 0,
      bloqueJusqua: Number(ligne.bloqueJusqua) || 0
    };
  };
  return {
    lire,
    async ecrire(cle, etat) {
      const existant = await adaptateur.findOne({ model: MODELE_TENTATIVE, where: ou(cle) });
      if (existant) await adaptateur.update({ model: MODELE_TENTATIVE, where: ou(cle), update: { ...etat } });
      else await adaptateur.create({ model: MODELE_TENTATIVE, data: { cle, ...etat } });
    },
    async effacer(cle) {
      await adaptateur.delete({ model: MODELE_TENTATIVE, where: ou(cle) });
    }
  };
}
function cleMotDePasse(email) {
  return `mdp:${email.trim().toLowerCase()}`;
}
function cle2fa(userId) {
  return `2fa:${userId}`;
}
function delaiAvantEssai(echecs, options = {}) {
  const palier = options.echecsAvantDelai ?? 3;
  if (echecs < palier) return 0;
  const initial = options.delaiInitialMs ?? 1e3;
  const max = options.delaiMaxMs ?? 3e4;
  return Math.min(initial * 2 ** (echecs - palier), max);
}
function apresEchec(etat, maintenant, options = {}) {
  const oubli = options.oubliApresMs ?? 24 * 60 * 60 * 1e3;
  const repart = !etat || maintenant - etat.dernierEchec > oubli || etat.bloqueJusqua > 0 && etat.bloqueJusqua <= maintenant;
  const echecs = (repart ? 0 : etat.echecs) + 1;
  const seuil = options.echecsAvantBlocage ?? 10;
  const duree = options.dureeBlocageMs ?? 15 * 60 * 1e3;
  return { echecs, dernierEchec: maintenant, bloqueJusqua: echecs >= seuil ? maintenant + duree : 0 };
}
function refusAvantEssai(etat, maintenant, options = {}) {
  if (!etat) return null;
  if (etat.bloqueJusqua > maintenant) return { raison: "bloque", attenteMs: etat.bloqueJusqua - maintenant };
  if (etat.bloqueJusqua > 0) return null;
  if (maintenant - etat.dernierEchec > (options.oubliApresMs ?? 24 * 60 * 60 * 1e3)) return null;
  const attente = etat.dernierEchec + delaiAvantEssai(etat.echecs, options) - maintenant;
  return attente > 0 ? { raison: "delai", attenteMs: attente } : null;
}
async function utilisateurEn2fa(ctx) {
  try {
    const session = await getSessionFromCtx(ctx);
    if (session?.user?.id) return session.user.id;
  } catch {
  }
  try {
    const cookie = ctx.context.createAuthCookie("two_factor");
    const jeton = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
    if (!jeton) return null;
    const verification = await ctx.context.internalAdapter.findVerificationValue(jeton);
    return verification?.value ?? null;
  } catch {
    return null;
  }
}
function emailDuCorps(ctx) {
  const email = ctx.body?.email;
  return typeof email === "string" && email.trim() ? email : null;
}
async function utilisateurConnecte(ctx) {
  try {
    const session = await getSessionFromCtx(ctx);
    return session?.user ?? null;
  } catch {
    return null;
  }
}
async function utilisateurDuLien(ctx) {
  const jeton = ctx.body?.token ?? ctx.query?.token;
  if (typeof jeton !== "string" || !jeton) return null;
  try {
    const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${jeton}`);
    if (!verification?.value) return null;
    if (verification.expiresAt && new Date(verification.expiresAt).getTime() < Date.now()) return null;
    return await ctx.context.internalAdapter.findUserById(verification.value);
  } catch {
    return null;
  }
}
var tentativesEnerlia = (options = {}) => {
  const cheminsMotDePasse = new Set(options.cheminsMotDePasse ?? CHEMINS_MOT_DE_PASSE);
  const chemins2fa = new Set(options.chemins2fa ?? CHEMINS_2FA);
  let stockageParDefaut = null;
  const stockage = (ctx) => {
    if (options.stockage) return options.stockage;
    stockageParDefaut ??= stockageBase(ctx.context.adapter);
    return stockageParDefaut;
  };
  const cleAvant = async (ctx) => {
    if (ctx.path && cheminsMotDePasse.has(ctx.path)) {
      const email = emailDuCorps(ctx);
      return email ? cleMotDePasse(email) : null;
    }
    if (ctx.path && chemins2fa.has(ctx.path)) {
      const userId = await utilisateurEn2fa(ctx);
      return userId ? cle2fa(userId) : null;
    }
    return null;
  };
  const debloquer = async (ctx, utilisateur) => {
    if (!utilisateur) return;
    try {
      if (utilisateur.email) await stockage(ctx).effacer(cleMotDePasse(utilisateur.email));
      if (utilisateur.id) await stockage(ctx).effacer(cle2fa(utilisateur.id));
    } catch {
    }
  };
  const estCheminDeblocage = (chemin) => chemin === CHEMIN_LIEN_REINITIALISATION || chemin === CHEMIN_ADMIN || CHEMINS_REINITIALISATION_PAR_EMAIL.has(chemin) || CHEMINS_CHANGEMENT_CONNECTE.has(chemin);
  const plugin = {
    id: "enerlia-tentatives",
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === CHEMIN_LIEN_REINITIALISATION,
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            await debloquer(c, await utilisateurDuLien(c));
          })
        },
        {
          matcher: (ctx) => !!ctx.path && (cheminsMotDePasse.has(ctx.path) || chemins2fa.has(ctx.path)),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            const cle = await cleAvant(c);
            if (!cle) return;
            const refus = refusAvantEssai(await stockage(c).lire(cle), Date.now(), options);
            if (!refus) return;
            const secondes = Math.max(1, Math.ceil(refus.attenteMs / 1e3));
            throw new APIError(
              "TOO_MANY_REQUESTS",
              refus.raison === "bloque" ? { message: MESSAGE_COMPTE_BLOQUE, code: "COMPTE_TEMPORAIREMENT_BLOQUE" } : { message: MESSAGE_DELAI, code: "TENTATIVE_TROP_RAPIDE" },
              { "Retry-After": String(secondes) }
            );
          })
        }
      ],
      after: [
        {
          matcher: (ctx) => !!ctx.path && ctx.path !== CHEMIN_LIEN_REINITIALISATION && estCheminDeblocage(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            if (estErreurApi(c.context.returned) || !c.path) return;
            if (CHEMINS_CHANGEMENT_CONNECTE.has(c.path)) return debloquer(c, await utilisateurConnecte(c));
            if (c.path === CHEMIN_ADMIN) {
              const userId = c.body?.userId;
              if (typeof userId === "string") await debloquer(c, await c.context.internalAdapter.findUserById(userId));
              return;
            }
            const email = emailDuCorps(c);
            if (!email) return;
            const trouve = await c.context.internalAdapter.findUserByEmail(email).catch(() => null);
            await debloquer(c, trouve?.user ?? { email });
          })
        },
        {
          matcher: (ctx) => !!ctx.path && (cheminsMotDePasse.has(ctx.path) || chemins2fa.has(ctx.path)),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            const resultat = c.context.returned;
            if (estErreurApi(resultat)) {
              const code = codeErreur(resultat);
              if (resultat.statusCode !== 401 || code && ERREURS_NON_COMPTEES.has(code)) return;
              const cle = await cleAvant(c);
              if (!cle) return;
              const etat = await stockage(c).lire(cle);
              await stockage(c).ecrire(cle, apresEchec(etat, Date.now(), options));
              return;
            }
            if (c.path && cheminsMotDePasse.has(c.path)) {
              const email = emailDuCorps(c);
              if (email) await stockage(c).effacer(cleMotDePasse(email));
              return;
            }
            const userId = c.context.newSession?.user?.id ?? resultat?.user?.id ?? await utilisateurEn2fa(c);
            if (userId) await stockage(c).effacer(cle2fa(userId));
          })
        }
      ]
    },
    ...options.stockage ? {} : {
      schema: {
        [MODELE_TENTATIVE]: {
          fields: {
            cle: { type: "string", required: true, unique: true },
            echecs: { type: "number", required: true },
            dernierEchec: { type: "number", required: true },
            bloqueJusqua: { type: "number", required: true }
          }
        }
      }
    }
  };
  return plugin;
};

export {
  MODELE_TENTATIVE,
  MESSAGE_COMPTE_BLOQUE,
  MESSAGE_DELAI,
  stockageMemoire,
  cleMotDePasse,
  cle2fa,
  delaiAvantEssai,
  apresEchec,
  refusAvantEssai,
  tentativesEnerlia
};
