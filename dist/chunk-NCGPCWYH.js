// src/erreurs.ts
function estErreurApi(valeur) {
  return typeof valeur === "object" && valeur !== null && "statusCode" in valeur && typeof valeur.statusCode === "number";
}
function codeErreur(erreur) {
  const code = erreur.body?.code;
  return typeof code === "string" ? code : void 0;
}
function messageErreur(erreur) {
  const message = erreur.body?.message ?? erreur.message;
  return typeof message === "string" ? message : "";
}

export {
  estErreurApi,
  codeErreur,
  messageErreur
};
