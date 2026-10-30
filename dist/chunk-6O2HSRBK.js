import {
  verifierMotDePasse
} from "./chunk-6OJ4WYWF.js";
import {
  estErreurApi
} from "./chunk-NCGPCWYH.js";

// src/controle-connexion.ts
import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
var CHEMINS_CONNEXION = /* @__PURE__ */ new Set(["/sign-in/email", "/sign-up/email"]);
var CHEMINS_NOUVEAU_MOT_DE_PASSE = /* @__PURE__ */ new Map([
  ["/change-password", "newPassword"],
  ["/set-password", "newPassword"]
]);
var CHEMINS_SESSION = /* @__PURE__ */ new Set(["/get-session", "/convex/token"]);
var PWNED_URL = "https://api.pwnedpasswords.com/range/";
async function estMotDePasseCompromis(motDePasse, delaiMs = 3e3) {
  try {
    const empreinte = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(motDePasse.normalize("NFC")));
    const hash = Array.from(new Uint8Array(empreinte), (o) => o.toString(16).padStart(2, "0")).join("").toUpperCase();
    let minuteur;
    const delai = new Promise((resoudre) => {
      minuteur = setTimeout(() => resoudre(null), delaiMs);
    });
    const requete = fetch(`${PWNED_URL}${hash.slice(0, 5)}`, { headers: { "Add-Padding": "true" } }).then(
      (r) => r.ok ? r.text() : null
    );
    const corps = await Promise.race([requete, delai]).finally(() => clearTimeout(minuteur));
    if (!corps) return false;
    const suffixe = hash.slice(5);
    return corps.split("\n").some((ligne) => {
      const [candidat, nombre] = ligne.trim().split(":");
      return candidat === suffixe && Number(nombre) > 0;
    });
  } catch {
    return false;
  }
}
async function utilisateurConnecte(ctx) {
  try {
    return (await getSessionFromCtx(ctx))?.user ?? null;
  } catch {
    return null;
  }
}
var controleConnexionEnerlia = (options) => {
  const conforme = async (motDePasse, utilisateur, appName) => {
    const refus = verifierMotDePasse(
      motDePasse,
      { email: utilisateur.email, nom: utilisateur.name, application: options.nomApplication ?? appName },
      options
    );
    if (refus) return false;
    if (options.verifierFuites === false) return true;
    return !await estMotDePasseCompromis(motDePasse, options.delaiFuitesMs);
  };
  const controler = async (c, motDePasse, utilisateur) => {
    if (typeof motDePasse !== "string" || !utilisateur?.id) return;
    try {
      await options.enregistrer({ userId: utilisateur.id, conforme: await conforme(motDePasse, utilisateur, c.context.appName) });
    } catch {
    }
  };
  return {
    id: "enerlia-controle-connexion",
    hooks: {
      before: [
        {
          matcher: (ctx) => !!options.estControle && !!ctx.path && CHEMINS_SESSION.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            const utilisateur = await utilisateurConnecte(c);
            if (!utilisateur?.id || !options.estControle) return;
            let controle = true;
            try {
              controle = await options.estControle(utilisateur.id);
            } catch {
              return;
            }
            if (controle) return;
            await c.context.internalAdapter.deleteUserSessions(utilisateur.id);
            c.context.session = null;
          })
        }
      ],
      after: [
        {
          matcher: (ctx) => !!ctx.path && CHEMINS_CONNEXION.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            if (estErreurApi(c.context.returned)) return;
            const email = c.body?.email;
            const utilisateur = c.context.newSession?.user ?? (typeof email === "string" ? (await c.context.internalAdapter.findUserByEmail(email).catch(() => null))?.user ?? null : null);
            await controler(c, c.body?.password, utilisateur);
          })
        },
        {
          matcher: (ctx) => !!ctx.path && CHEMINS_NOUVEAU_MOT_DE_PASSE.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            if (estErreurApi(c.context.returned) || !c.path) return;
            const champ = CHEMINS_NOUVEAU_MOT_DE_PASSE.get(c.path) ?? "newPassword";
            await controler(c, c.body?.[champ], await utilisateurConnecte(c));
          })
        }
      ]
    }
  };
};

export {
  estMotDePasseCompromis,
  controleConnexionEnerlia
};
