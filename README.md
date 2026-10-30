# enerlia-auth-secure

Plugins [Better Auth](https://www.better-auth.com) qui appliquent le référentiel Enerlia « Sécurité des comptes et des connexions » (v2.3 du 29 octobre 2026). Ils fonctionnent avec toute app Better Auth, qu’elle tourne sous Next.js, TanStack Start, Bun ou Convex.

| Plugin | Règle du référentiel | Ce qu’il fait |
|---|---|---|
| `dureeSessionEnerlia` | §5 Session | Plafonne chaque session à 7 jours après la connexion. Avec `session: sessionEnerlia`, la session expire aussi après 48 h sans activité. |
| `tentativesEnerlia` | §3 Force brute | Compteur d’échecs par compte, pour le mot de passe et les codes 2FA : délai croissant dès le 3e échec, blocage de 15 min au 10e, déblocage par un nouveau mot de passe. Aucun blocage par adresse IP : seul le compte visé est bloqué. |
| `envoisEmailEnerlia` | §3 Envois d’e-mails | Au plus 3 demandes de lien ou de code par e-mail en 10 minutes pour une même adresse (mot de passe oublié, code par e-mail, code 2FA, lien de connexion, routes de l’app comme le renvoi d’invitation). |
| `motDePasseEnerlia` | §1 Mot de passe | 14 à 128 caractères sans composition imposée, émojis refusés, accents normalisés, refus des mots de passe courants ou contenant l’e-mail, le nom ou le nom de l’app, contrôle des fuites avec le plugin officiel `haveIBeenPwned` et liste locale si le service ne répond pas. |
| `controleConnexionEnerlia` | §1 Mot de passe | Contrôle à chaque connexion réussie le mot de passe déjà enregistré, avec les mêmes règles, et transmet le résultat à l’app, qui impose alors le changement. Déconnecte une fois chaque utilisateur jamais contrôlé. Non inclus dans `securiteEnerlia()` : il demande du stockage côté app. |

Testé avec Better Auth 1.6.15 et 1.6.33, à chaque push, par la vérification automatique du dépôt (GitHub Actions).

Le dépôt est public : il ne contient que des règles de sécurité, sans clé, nom de client ni donnée. N’y ajouter aucun élément confidentiel. La mention `"private": true` du `package.json` empêche seulement une publication par erreur sur le registre npm.

## Installation

Le dépôt est public : l’installation depuis GitHub ne demande aucun jeton, en local comme dans la CI ou sur Dokploy. Toujours installer une version précise :

```bash
bun add github:ENERLIA/enerlia-auth-secure#v0.4.0
# ou
npm install github:ENERLIA/enerlia-auth-secure#v0.4.0
```

Le fichier de verrouillage (`bun.lock`, `package-lock.json`) retient le commit exact du tag. Le build de l’app installe donc toujours le même code.

Une copie du paquet dans l’app (dossier `vendor/`), utile quand le dépôt était privé, n’est plus nécessaire : l’installation depuis GitHub est plus simple à mettre à jour.

## Utilisation

```ts
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { securiteEnerlia, sessionEnerlia } from "enerlia-auth-secure";

export const auth = betterAuth({
  appName: "Nom de l’application", // refusé dans les mots de passe
  session: {
    ...sessionEnerlia, // 48 h sans activité, prolongée au plus une fois par heure
    freshAge: 10 * 60, // réauthentification au-delà de 10 minutes (§6)
    cookieCache: { enabled: true, maxAge: 5 * 60 }, // révocation prise en compte en 5 min maximum
  },
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 14,
    maxPasswordLength: 128,
    resetPasswordTokenExpiresIn: 60 * 60,
    revokeSessionsOnPasswordReset: true,
  },
  // Aucun blocage par adresse IP (§3) : la limite de Better Auth compte par IP et
  // bloquerait tous les collègues d’un même bureau. Les plugins Enerlia comptent par compte.
  rateLimit: { enabled: false },
  advanced: { useSecureCookies: true },
  plugins: [
    ...securiteEnerlia(),
    twoFactor({
      otpOptions: { period: 10, storeOTP: "hashed" },
      backupCodeOptions: { amount: 10, storeBackupCodes: "encrypted" },
    }),
  ],
});
```

Chaque plugin peut aussi être ajouté seul : `dureeSessionEnerlia()`, `tentativesEnerlia()`, `envoisEmailEnerlia()`, `motDePasseEnerlia()`. Pour en retirer un de `securiteEnerlia`, passer `false` : `securiteEnerlia({ envoisEmail: false })`.

### Stockage des compteurs

`tentativesEnerlia` et `envoisEmailEnerlia` partagent la table `enerliaTentative`, ajoutée par défaut à la base Better Auth. Il faut alors régénérer le schéma (`npx @better-auth/cli generate`, ou le schéma du composant Better Auth installé en local dans Convex).

Avec le composant `@convex-dev/better-auth` utilisé tel quel, on ne peut pas ajouter de table. Fournir alors un stockage qui écrit dans une table de l’app, et le passer aux deux plugins :

```ts
// convex/schema.ts
tentativesConnexion: defineTable({
  cle: v.string(),
  echecs: v.number(),
  dernierEchec: v.number(),
  bloqueJusqua: v.number(),
}).index("par_cle", ["cle"]),

// convex/auth.ts, dans createAuth(ctx)
const stockage = {
  lire: (cle) => ctx.runQuery(internal.tentatives.lire, { cle }),
  ecrire: (cle, etat) => ctx.runMutation(internal.tentatives.ecrire, { cle, ...etat }),
  effacer: (cle) => ctx.runMutation(internal.tentatives.effacer, { cle }),
};
// …
plugins: [...securiteEnerlia({ tentatives: { stockage }, envoisEmail: { stockage } })],
```

Les clés ne se mélangent pas : `mdp:` et `2fa:` pour les échecs, `envoi:` et `envoi-2fa:` pour les e-mails.

### Routes propres à l’app

`motDePasseEnerlia` contrôle les routes Better Auth où l’on choisit un mot de passe. `envoisEmailEnerlia` limite les routes Better Auth qui envoient un lien ou un code. Si l’app a ses propres routes, il faut les déclarer :

```ts
securiteEnerlia({
  motDePasse: { routesSupplementaires: [{ chemin: "/invitation/activate-password", champ: "password" }] },
  envoisEmail: { routesSupplementaires: [{ chemin: "/invitation/resend", champ: "email" }] },
});
```

Une route d’envoi qui n’est pas une route Better Auth (mutation Convex, action serveur) n’est pas couverte : appliquer la même règle dans l’app, avec `compterDemande` exportée par le paquet.

## Ce que Better Auth fait déjà, à régler dans l’app

Ces règles du référentiel existent dans Better Auth, mais ses réglages par défaut ne sont pas conformes. L’exemple ci-dessus les pose :

| Règle | Réglage |
|---|---|
| Aucun blocage par adresse IP | `rateLimit: { enabled: false }` (actif par défaut en production) |
| Révocation en 5 minutes au plus | `session.cookieCache.maxAge: 300` |
| Réauthentification au-delà de 10 minutes sur les routes Better Auth | `session.freshAge: 600` (24 h par défaut) |
| Lien de réinitialisation valable 1 h, autres sessions fermées après réinitialisation | `resetPasswordTokenExpiresIn: 3600`, `revokeSessionsOnPasswordReset: true` |
| Codes de secours chiffrés | `backupCodeOptions.storeBackupCodes: "encrypted"` (stockés en clair par défaut) |
| Code 2FA par e-mail haché, valable 10 min au plus | `otpOptions: { period: 10, storeOTP: "hashed" }` |
| Pas d’appareil de confiance | `trustDevice: false` côté client lors de la vérification 2FA (30 jours sinon) |
| Invitation valable 72 h | `organization({ invitationExpiresIn: 72 * 3600 })` (48 h par défaut) |

## Ce qui reste à la charge de l’app

- 2FA obligatoire pour les comptes internes, contrôlée côté serveur dans chaque fonction protégée.
- Réauthentification avant une action sensible hors routes Better Auth (§6).
- Notifications par e-mail : nouvel appareil, changement de mot de passe, d’e-mail ou de 2FA (§7).
- En-têtes HTTP `Content-Security-Policy` et `X-Content-Type-Options` (§8).
- Avec `controleConnexionEnerlia` : stocker le résultat du contrôle, bloquer côté serveur un compte dont le mot de passe est à changer (sauf lecture de son profil et changement de mot de passe), et l’envoyer sur un écran de changement.

## Mots de passe déjà enregistrés

`motDePasseEnerlia` s’applique quand un mot de passe est choisi. Un mot de passe plus ancien (trop court, devenu public dans une fuite) reste utilisable. `controleConnexionEnerlia` le contrôle à la connexion, seul moment où il est connu en clair :

```ts
controleConnexionEnerlia({
  nomApplication: "Nom de l’application",
  // Après chaque connexion réussie, et après le choix d’un nouveau mot de passe par un utilisateur connecté.
  enregistrer: ({ userId, conforme }) => ctx.runMutation(internal.motDePasse.enregistrerControle, { authId: userId, conforme }),
  // Faux tant que le mot de passe n’a jamais été contrôlé : ses sessions sont fermées.
  estControle: (userId) => ctx.runQuery(internal.motDePasse.estControle, { authId: userId }),
}),
```

- **À la connexion** et **à la création du compte** (`/sign-in/email`, `/sign-up/email`), après un mot de passe juste, y compris quand la double authentification attend encore son code, le plugin vérifie les règles et les fuites connues, puis appelle `enregistrer`. Rien n’est conservé : seul `conforme` sort. Le contrôle ne bloque jamais la connexion : une erreur ou un service de fuites injoignable laisse passer, la liste locale restant appliquée.
- **Après un changement** de mot de passe par un utilisateur connecté (`/change-password`, `/set-password`), le nouveau mot de passe est contrôlé de la même façon : l’app peut lever l’obligation. Après une réinitialisation par lien ou par code, c’est la connexion suivante qui fait le contrôle.
- **Déconnexion unique** : à la lecture de la session (`/get-session`) ou du jeton Convex (`/convex/token`), si `estControle` répond faux, toutes les sessions de l’utilisateur sont fermées. Il se reconnecte, et sa connexion fait le contrôle. Avec `session.cookieCache`, la déconnexion attend la fin du cache. Un jeton Convex déjà émis reste valable jusqu’à son expiration : l’app doit aussi refuser, dans ses gardes serveur, un compte jamais contrôlé.

## Comportements à connaître

- **Session :** à chaque prolongation, l’expiration est ramenée au plus à la connexion + 7 jours. La session s’arrête donc à 7 jours pile, même si l’utilisateur est actif, puis il se reconnecte.
- **Tentatives :** les essais sur une adresse e-mail inconnue sont comptés comme les autres, pour ne pas révéler l’existence d’un compte. Un tiers qui connaît une adresse peut la faire bloquer 15 minutes ; la réinitialisation du mot de passe la débloque. Aucune adresse IP n’est jamais bloquée : les collègues qui partagent la même connexion ne sont pas touchés.
- **Envois d’e-mails :** la 4e demande en 10 minutes pour la même adresse reçoit une erreur 429 « Trop de demandes pour cette adresse e-mail » et aucun e-mail ne part. La réponse est la même que le compte existe ou non.
- **Fuites :** seuls les 5 premiers caractères de l’empreinte SHA-1 sont envoyés à Pwned Passwords. Si le service ne répond pas, le mot de passe est accepté après le contrôle de la liste locale.

## Changements

- **0.5.1** — `controleConnexionEnerlia` contrôle aussi le mot de passe choisi à la création du compte : un nouvel invité n’est pas déconnecté.
- **0.5.0** — Nouveau plugin `controleConnexionEnerlia` : contrôle à la connexion des mots de passe déjà enregistrés, déconnexion unique des comptes jamais contrôlés. Fonction `estMotDePasseCompromis`.
- **0.4.0** — Alignement sur le référentiel v2.3 : suppression de la limite par adresse IP de `tentativesEnerlia` (options `echecsParIp` et `fenetreIpMs` retirées), nouveau plugin `envoisEmailEnerlia` (3 e-mails en 10 minutes par adresse), README : `rateLimit` désactivé et réglages Better Auth à poser.
- **0.3.0** — Longueur minimale du mot de passe portée à 14 caractères.
- **0.2.0** — Le blocage d’un compte ne gêne plus les collègues du même réseau.
- **0.1.0** — Premiers plugins : durée des sessions, tentatives et blocage par compte, règles de mot de passe.

## Développement

```bash
bun install
bun run check   # types, tests, build
```

Le dossier `dist` est versionné pour l’installation depuis GitHub : relancer `bun run build` avant chaque commit qui modifie `src`. Publier une version : mettre à jour `version` dans `package.json`, puis créer le tag `vX.Y.Z`.

La vérification automatique (`.github/workflows/verifications.yml`) lance les tests avec Better Auth 1.6.15 et 1.6.33, puis contrôle que `dist` correspond bien au code de `src`.
