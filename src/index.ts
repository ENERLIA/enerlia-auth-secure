export * from "./session";
export * from "./tentatives";
export * from "./mot-de-passe";
export * from "./envois-email";
export { MOTS_DE_PASSE_COURANTS, estMotDePasseCourant } from "./mots-de-passe-courants";

import { dureeSessionEnerlia, type OptionsDureeSession } from "./session";
import { motDePasseEnerlia, type OptionsMotDePasse } from "./mot-de-passe";
import { tentativesEnerlia, type OptionsTentatives } from "./tentatives";
import { envoisEmailEnerlia, type OptionsEnvoisEmail } from "./envois-email";

export type OptionsSecuriteEnerlia = {
  session?: OptionsDureeSession | false;
  tentatives?: OptionsTentatives | false;
  motDePasse?: OptionsMotDePasse | false;
  envoisEmail?: OptionsEnvoisEmail | false;
};

/**
 * Tous les plugins du référentiel Enerlia, à étaler dans `plugins` :
 * `plugins: [...securiteEnerlia({ ... }), twoFactor(), ...]`.
 * Penser aussi à `session: sessionEnerlia` dans la configuration Better Auth.
 */
export function securiteEnerlia(options: OptionsSecuriteEnerlia = {}) {
  return [
    ...(options.session === false ? [] : [dureeSessionEnerlia(options.session)]),
    ...(options.tentatives === false ? [] : [tentativesEnerlia(options.tentatives)]),
    ...(options.motDePasse === false ? [] : [motDePasseEnerlia(options.motDePasse)]),
    ...(options.envoisEmail === false ? [] : [envoisEmailEnerlia(options.envoisEmail)]),
  ];
}
