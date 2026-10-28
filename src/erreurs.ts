/** Détection d'une erreur Better Auth sans dépendre de l'identité de la classe (plusieurs copies possibles). */
export type ErreurApi = { status?: unknown; statusCode?: unknown; body?: { code?: unknown; message?: unknown } };

export function estErreurApi(valeur: unknown): valeur is ErreurApi {
  return (
    typeof valeur === "object" &&
    valeur !== null &&
    "statusCode" in valeur &&
    typeof (valeur as { statusCode: unknown }).statusCode === "number"
  );
}

export function codeErreur(erreur: ErreurApi): string | undefined {
  const code = erreur.body?.code;
  return typeof code === "string" ? code : undefined;
}

export function messageErreur(erreur: ErreurApi): string {
  const message = erreur.body?.message ?? (erreur as { message?: unknown }).message;
  return typeof message === "string" ? message : "";
}
