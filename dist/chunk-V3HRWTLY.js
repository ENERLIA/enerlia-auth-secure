import {
  SCHEMA_TENTATIVE,
  stockageBase,
  utilisateurEn2fa
} from "./chunk-JFKTIXMC.js";

// src/envois-email.ts
import { APIError, createAuthMiddleware } from "better-auth/api";
var ROUTES_ENVOI_EMAIL = [
  { chemin: "/request-password-reset", champ: "email" },
  { chemin: "/email-otp/request-password-reset", champ: "email" },
  { chemin: "/forget-password/email-otp", champ: "email" },
  { chemin: "/email-otp/send-verification-otp", champ: "email" },
  { chemin: "/send-verification-email", champ: "email" },
  { chemin: "/sign-in/magic-link", champ: "email" }
];
var CHEMIN_CODE_2FA = "/two-factor/send-otp";
var MESSAGE_TROP_DE_DEMANDES = "Trop de demandes pour cette adresse e-mail. R\xE9essayez dans quelques minutes.";
function cleEnvoiEmail(email) {
  return `envoi:${email.trim().toLowerCase()}`;
}
function cleEnvoi2fa(userId) {
  return `envoi-2fa:${userId}`;
}
function compterDemande(etat, maintenant, options = {}) {
  const max = options.maxDemandes ?? 3;
  const fenetre = options.fenetreMs ?? 10 * 60 * 1e3;
  if (!etat || etat.bloqueJusqua <= maintenant) {
    return { accepte: true, etat: { echecs: 1, dernierEchec: maintenant, bloqueJusqua: maintenant + fenetre } };
  }
  if (etat.echecs >= max) return { accepte: false, attenteMs: etat.bloqueJusqua - maintenant };
  return { accepte: true, etat: { echecs: etat.echecs + 1, dernierEchec: maintenant, bloqueJusqua: etat.bloqueJusqua } };
}
var envoisEmailEnerlia = (options = {}) => {
  const champParChemin = new Map(
    [...ROUTES_ENVOI_EMAIL, ...options.routesSupplementaires ?? []].map((r) => [r.chemin, r.champ])
  );
  let stockageParDefaut = null;
  const stockage = (ctx) => {
    if (options.stockage) return options.stockage;
    stockageParDefaut ??= stockageBase(ctx.context.adapter);
    return stockageParDefaut;
  };
  const cleDe = async (ctx) => {
    if (!ctx.path) return null;
    if (ctx.path === CHEMIN_CODE_2FA) {
      const userId = await utilisateurEn2fa(ctx);
      return userId ? cleEnvoi2fa(userId) : null;
    }
    const champ = champParChemin.get(ctx.path);
    const email = champ ? ctx.body?.[champ] : void 0;
    return typeof email === "string" && email.trim() ? cleEnvoiEmail(email) : null;
  };
  return {
    id: "enerlia-envois-email",
    hooks: {
      before: [
        {
          matcher: (ctx) => !!ctx.path && (ctx.path === CHEMIN_CODE_2FA || champParChemin.has(ctx.path)),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            const cle = await cleDe(c);
            if (!cle) return;
            const decision = compterDemande(await stockage(c).lire(cle), Date.now(), options);
            if (decision.accepte) {
              await stockage(c).ecrire(cle, decision.etat);
              return;
            }
            throw new APIError(
              "TOO_MANY_REQUESTS",
              { message: MESSAGE_TROP_DE_DEMANDES, code: "TROP_DE_DEMANDES_EMAIL" },
              { "Retry-After": String(Math.max(1, Math.ceil(decision.attenteMs / 1e3))) }
            );
          })
        }
      ]
    },
    ...options.stockage ? {} : { schema: SCHEMA_TENTATIVE }
  };
};

export {
  ROUTES_ENVOI_EMAIL,
  MESSAGE_TROP_DE_DEMANDES,
  cleEnvoiEmail,
  cleEnvoi2fa,
  compterDemande,
  envoisEmailEnerlia
};
