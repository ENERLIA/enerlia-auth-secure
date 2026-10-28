import {
  estErreurApi,
  messageErreur
} from "./chunk-NCGPCWYH.js";

// src/mot-de-passe.ts
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { haveIBeenPwned } from "better-auth/plugins/haveibeenpwned";

// src/mots-de-passe-courants.ts
var MOTS_DE_PASSE_COURANTS = [
  "motdepasse123",
  "motdepasse1234",
  "motdepasse2024",
  "motdepasse2025",
  "motdepasse2026",
  "monmotdepasse",
  "monmotdepasse1",
  "monmotdepasse123",
  "motdepassesecret",
  "motdepassesecure",
  "password1234",
  "password12345",
  "password123456",
  "passwordpassword",
  "mypassword123",
  "azertyuiop123",
  "azertyuiop1234",
  "azertyuiopqsdf",
  "azertyuiopqsdfghjklm",
  "azerty123456",
  "azerty1234567",
  "azertyazerty",
  "qwertyuiop123",
  "qwertyuiop1234",
  "qwerty123456",
  "qwertyqwerty",
  "qwertyuiopasdf",
  "1q2w3e4r5t6y",
  "1q2w3e4r5t6y7u",
  "1a2z3e4r5t6y",
  "iloveyou1234",
  "jetaime123456",
  "jetaimetoujours",
  "bonjour123456",
  "soleil123456",
  "doudou123456",
  "chouchou1234",
  "loulou123456",
  "marseille13013",
  "liverpool1234",
  "football1234",
  "football12345",
  "baseball1234",
  "superman1234",
  "batman123456",
  "welcome12345",
  "welcome123456",
  "bienvenue123",
  "bienvenue1234",
  "administrateur",
  "administrator",
  "admin1234567",
  "adminadmin123",
  "changeme1234",
  "changezmoi123",
  "letmein12345",
  "trustno11234",
  "starwars1234",
  "princesse123",
  "nicolas12345",
  "abcdefgh1234",
  "abc123456789",
  "123456789abc",
  "1234567890ab",
  "123456789azerty",
  "0123456789ab",
  "aaaaaa123456",
  "1234qwerasdf",
  "1234azerqsdf",
  "zaq12wsxcde3",
  "1qaz2wsx3edc",
  "qazwsxedcrfv",
  "passw0rd1234",
  "p@ssw0rd1234",
  "p@ssword1234",
  "m0td3p4ss3123",
  "motdepasse!!",
  "motdepasse123!",
  "azerty123456!",
  "password1234!"
];
var SUITES = [
  "0123456789012345678901234567890",
  "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
  "azertyuiopqsdfghjklmwxcvbn",
  "qwertyuiopasdfghjklzxcvbnm"
];
function estMotDePasseCourant(motDePasse, liste = MOTS_DE_PASSE_COURANTS) {
  const simple = motDePasse.toLowerCase();
  if (liste.includes(simple)) return true;
  if (/^(.{1,4})\1+$/u.test(simple)) return true;
  for (const suite of SUITES) {
    const inverse = [...suite].reverse().join("");
    if (suite.includes(simple) || inverse.includes(simple)) return true;
  }
  return false;
}

// src/mot-de-passe.ts
var ROUTES_MOT_DE_PASSE = [
  { chemin: "/sign-up/email", champ: "password" },
  { chemin: "/change-password", champ: "newPassword" },
  { chemin: "/set-password", champ: "newPassword" },
  { chemin: "/reset-password", champ: "newPassword" },
  { chemin: "/email-otp/reset-password", champ: "password" },
  { chemin: "/admin/create-user", champ: "password" },
  { chemin: "/admin/set-user-password", champ: "newPassword" }
];
var MESSAGES_MOT_DE_PASSE = {
  MOT_DE_PASSE_TROP_COURT: (min) => `Le mot de passe doit contenir au moins ${min} caract\xE8res.`,
  MOT_DE_PASSE_TROP_LONG: (max) => `Le mot de passe doit contenir au plus ${max} caract\xE8res.`,
  MOT_DE_PASSE_EMOJI: "Le mot de passe ne peut pas contenir d'\xE9moji.",
  MOT_DE_PASSE_COURANT: "Ce mot de passe est trop courant. Choisissez-en un autre.",
  MOT_DE_PASSE_PERSONNEL: "Le mot de passe ne doit contenir ni votre adresse e-mail, ni votre nom, ni le nom de l'application.",
  MOT_DE_PASSE_COMPROMIS: "Ce mot de passe figure dans une fuite de donn\xE9es connue. Choisissez-en un autre."
};
var EMOJI = /\p{Extended_Pictographic}|\p{Regional_Indicator}|\u{FE0F}/u;
function simplifier(texte) {
  return texte.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
}
function fragmentsPersonnels(infos) {
  const fragments = /* @__PURE__ */ new Set();
  const ajouter = (texte) => {
    if (!texte) return;
    const simple = simplifier(texte);
    for (const mot of simple.split(/[^\p{L}\p{N}]+/u)) if (mot.length >= 4) fragments.add(mot);
    const colle = simple.replace(/[^\p{L}\p{N}]+/gu, "");
    if (colle.length >= 4) fragments.add(colle);
  };
  if (infos.email) ajouter(infos.email.split("@")[0]);
  ajouter(infos.nom);
  ajouter(infos.application);
  return [...fragments];
}
function verifierMotDePasse(motDePasse, infos = {}, options = {}) {
  const normalise = motDePasse.normalize("NFC");
  const longueur = [...normalise].length;
  if (longueur < (options.longueurMin ?? 12)) return "MOT_DE_PASSE_TROP_COURT";
  if (longueur > (options.longueurMax ?? 128)) return "MOT_DE_PASSE_TROP_LONG";
  if (EMOJI.test(normalise)) return "MOT_DE_PASSE_EMOJI";
  const liste = options.motsInterdits?.length ? [...MOTS_DE_PASSE_COURANTS, ...options.motsInterdits.map((m) => m.toLowerCase())] : MOTS_DE_PASSE_COURANTS;
  if (estMotDePasseCourant(normalise, liste)) return "MOT_DE_PASSE_COURANT";
  const simple = simplifier(normalise).replace(/\s+/g, "");
  if (fragmentsPersonnels(infos).some((fragment) => simple.includes(fragment))) return "MOT_DE_PASSE_PERSONNEL";
  return null;
}
async function personneConcernee(ctx) {
  const corps = ctx.body ?? {};
  const texte = (valeur) => typeof valeur === "string" && valeur ? valeur : void 0;
  let email = texte(corps.email);
  let nom = texte(corps.name);
  const completer = (utilisateur) => {
    email ??= texte(utilisateur?.email);
    nom ??= texte(utilisateur?.name);
  };
  try {
    if (typeof corps.userId === "string") completer(await ctx.context.internalAdapter.findUserById(corps.userId));
    const jeton = corps.token ?? ctx.query?.token;
    if (ctx.path === "/reset-password" && typeof jeton === "string" && jeton) {
      const verification = await ctx.context.internalAdapter.findVerificationValue(`reset-password:${jeton}`);
      if (verification?.value) completer(await ctx.context.internalAdapter.findUserById(verification.value));
    }
    if (!email || !nom) completer((await getSessionFromCtx(ctx))?.user);
  } catch {
  }
  return { email, nom };
}
var motDePasseEnerlia = (options = {}) => {
  const routes = [...ROUTES_MOT_DE_PASSE, ...options.routesSupplementaires ?? []];
  const champParChemin = new Map(routes.map((r) => [r.chemin, r.champ]));
  const fuites = haveIBeenPwned({
    paths: routes.map((r) => r.chemin),
    customPasswordCompromisedMessage: MESSAGES_MOT_DE_PASSE.MOT_DE_PASSE_COMPROMIS
  });
  return {
    id: "enerlia-mot-de-passe",
    init(contexte) {
      const original = contexte.password;
      const avecFuites = options.verifierFuites === false ? original : fuites.init(contexte).context.password;
      return {
        context: {
          password: {
            ...original,
            async hash(motDePasse) {
              const normalise = motDePasse.normalize("NFC");
              try {
                return await avecFuites.hash(normalise);
              } catch (erreur) {
                if (estErreurApi(erreur) && erreur.statusCode === 500 && messageErreur(erreur).startsWith("Failed to check password")) {
                  return original.hash(normalise);
                }
                throw erreur;
              }
            },
            async verify(donnees) {
              const normalise = donnees.password.normalize("NFC");
              if (await original.verify({ ...donnees, password: normalise })) return true;
              return normalise !== donnees.password && original.verify(donnees);
            }
          }
        }
      };
    },
    hooks: {
      before: [
        {
          matcher: (ctx) => !!ctx.path && champParChemin.has(ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const c = ctx;
            const champ = c.path ? champParChemin.get(c.path) : void 0;
            const motDePasse = champ ? c.body?.[champ] : void 0;
            if (typeof motDePasse !== "string") return;
            const personne = await personneConcernee(c);
            const refus = verifierMotDePasse(
              motDePasse,
              { ...personne, application: options.nomApplication ?? c.context.appName },
              options
            );
            if (!refus) return;
            const message = refus === "MOT_DE_PASSE_TROP_COURT" ? MESSAGES_MOT_DE_PASSE.MOT_DE_PASSE_TROP_COURT(options.longueurMin ?? 12) : refus === "MOT_DE_PASSE_TROP_LONG" ? MESSAGES_MOT_DE_PASSE.MOT_DE_PASSE_TROP_LONG(options.longueurMax ?? 128) : MESSAGES_MOT_DE_PASSE[refus];
            throw new APIError("BAD_REQUEST", { message, code: refus });
          })
        }
      ]
    }
  };
};

export {
  MOTS_DE_PASSE_COURANTS,
  estMotDePasseCourant,
  ROUTES_MOT_DE_PASSE,
  MESSAGES_MOT_DE_PASSE,
  fragmentsPersonnels,
  verifierMotDePasse,
  motDePasseEnerlia
};
