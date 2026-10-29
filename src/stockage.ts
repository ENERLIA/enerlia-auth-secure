/**
 * Stockage des compteurs partagé par les plugins `tentativesEnerlia` et
 * `envoisEmailEnerlia`. Par défaut, une table `enerliaTentative` de la base
 * Better Auth ; l'application peut fournir son propre stockage.
 */

export type EtatTentatives = {
  /** Nombre d'échecs consécutifs, ou de demandes dans la fenêtre en cours. */
  echecs: number;
  /** Date du dernier échec ou de la dernière demande (ms depuis l'époque Unix). */
  dernierEchec: number;
  /**
   * Compte : fin du blocage (ms depuis l'époque Unix), 0 s'il n'est pas bloqué.
   * Envois d'e-mails : fin de la fenêtre de comptage en cours.
   */
  bloqueJusqua: number;
};

/** Où ranger les compteurs. Par défaut : une table de la base Better Auth. */
export interface StockageTentatives {
  lire(cle: string): Promise<EtatTentatives | null>;
  ecrire(cle: string, etat: EtatTentatives): Promise<void>;
  effacer(cle: string): Promise<void>;
}

export const MODELE_TENTATIVE = "enerliaTentative";

/** Table ajoutée à la base Better Auth quand aucun stockage n'est fourni. */
export const SCHEMA_TENTATIVE = {
  [MODELE_TENTATIVE]: {
    fields: {
      cle: { type: "string", required: true, unique: true },
      echecs: { type: "number", required: true },
      dernierEchec: { type: "number", required: true },
      bloqueJusqua: { type: "number", required: true },
    },
  },
} as const;

/** Stockage en mémoire, pour les tests et le développement local. */
export function stockageMemoire(): StockageTentatives & { donnees: Map<string, EtatTentatives> } {
  const donnees = new Map<string, EtatTentatives>();
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
    },
  };
}

type AdaptateurBase = {
  findOne<T>(args: { model: string; where: { field: string; value: string }[] }): Promise<T | null>;
  create<T>(args: { model: string; data: Record<string, unknown> }): Promise<T>;
  update<T>(args: { model: string; where: { field: string; value: string }[]; update: Record<string, unknown> }): Promise<T | null>;
  delete(args: { model: string; where: { field: string; value: string }[] }): Promise<void>;
};

/** Stockage dans la table `enerliaTentative` de la base Better Auth. */
export function stockageBase(adaptateur: unknown): StockageTentatives {
  const base = adaptateur as AdaptateurBase;
  const ou = (cle: string) => [{ field: "cle", value: cle }];
  return {
    async lire(cle) {
      const ligne = await base.findOne<Record<string, unknown>>({ model: MODELE_TENTATIVE, where: ou(cle) });
      if (!ligne) return null;
      return {
        echecs: Number(ligne.echecs) || 0,
        dernierEchec: Number(ligne.dernierEchec) || 0,
        bloqueJusqua: Number(ligne.bloqueJusqua) || 0,
      };
    },
    async ecrire(cle, etat) {
      const existant = await base.findOne<Record<string, unknown>>({ model: MODELE_TENTATIVE, where: ou(cle) });
      if (existant) await base.update({ model: MODELE_TENTATIVE, where: ou(cle), update: { ...etat } });
      else await base.create({ model: MODELE_TENTATIVE, data: { cle, ...etat } });
    },
    async effacer(cle) {
      await base.delete({ model: MODELE_TENTATIVE, where: ou(cle) });
    },
  };
}
