/**
 * Stockage des compteurs partagé par les plugins `tentativesEnerlia` et
 * `envoisEmailEnerlia`. Par défaut, une table `enerliaTentative` de la base
 * Better Auth ; l'application peut fournir son propre stockage.
 */
type EtatTentatives = {
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
interface StockageTentatives {
    lire(cle: string): Promise<EtatTentatives | null>;
    ecrire(cle: string, etat: EtatTentatives): Promise<void>;
    effacer(cle: string): Promise<void>;
}
declare const MODELE_TENTATIVE = "enerliaTentative";
/** Stockage en mémoire, pour les tests et le développement local. */
declare function stockageMemoire(): StockageTentatives & {
    donnees: Map<string, EtatTentatives>;
};

export { type EtatTentatives as E, MODELE_TENTATIVE as M, type StockageTentatives as S, stockageMemoire as s };
