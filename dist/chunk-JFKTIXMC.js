// src/deux-facteurs.ts
import { getSessionFromCtx } from "better-auth/api";
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

// src/stockage.ts
var MODELE_TENTATIVE = "enerliaTentative";
var SCHEMA_TENTATIVE = {
  [MODELE_TENTATIVE]: {
    fields: {
      cle: { type: "string", required: true, unique: true },
      echecs: { type: "number", required: true },
      dernierEchec: { type: "number", required: true },
      bloqueJusqua: { type: "number", required: true }
    }
  }
};
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
  const base = adaptateur;
  const ou = (cle) => [{ field: "cle", value: cle }];
  return {
    async lire(cle) {
      const ligne = await base.findOne({ model: MODELE_TENTATIVE, where: ou(cle) });
      if (!ligne) return null;
      return {
        echecs: Number(ligne.echecs) || 0,
        dernierEchec: Number(ligne.dernierEchec) || 0,
        bloqueJusqua: Number(ligne.bloqueJusqua) || 0
      };
    },
    async ecrire(cle, etat) {
      const existant = await base.findOne({ model: MODELE_TENTATIVE, where: ou(cle) });
      if (existant) await base.update({ model: MODELE_TENTATIVE, where: ou(cle), update: { ...etat } });
      else await base.create({ model: MODELE_TENTATIVE, data: { cle, ...etat } });
    },
    async effacer(cle) {
      await base.delete({ model: MODELE_TENTATIVE, where: ou(cle) });
    }
  };
}

export {
  utilisateurEn2fa,
  MODELE_TENTATIVE,
  SCHEMA_TENTATIVE,
  stockageMemoire,
  stockageBase
};
