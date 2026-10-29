# enerlia-auth-secure

Plugins [Better Auth](https://www.better-auth.com) qui appliquent le référentiel Enerlia « Sécurité des comptes et des connexions » (v2.1 du 29 octobre 2026). Ils fonctionnent avec toute app Better Auth, qu’elle tourne sous Next.js, TanStack Start, Bun ou Convex.

| Plugin | Règle du référentiel | Ce qu’il fait |
|---|---|---|
| `dureeSessionEnerlia` | §5 Session | Plafonne chaque session à 7 jours après la connexion. Avec `session: sessionEnerlia`, la session expire aussi après 48 h sans activité. |
| `tentativesEnerlia` | §3 Force brute | Compteur d’échecs par compte, pour le mot de passe et les codes 2FA : délai croissant dès le 3e échec, blocage de 15 min au 10e, déblocage par un nouveau mot de passe. Le blocage ne touche que le compte visé. Limite par adresse IP sur les seuls échecs : 50 en 15 minutes, tous comptes confondus. |
| `motDePasseEnerlia` | §1 Mot de passe | 12 à 128 caractères sans composition imposée, émojis refusés, accents normalisés, refus des mots de passe courants ou contenant l’e-mail, le nom ou le nom de l’app, contrôle des fuites avec le plugin officiel `haveIBeenPwned` et liste locale si le service ne répond pas. |

Testé avec Better Auth 1.6.15 et 1.6.33.

## Installation

Le paquet est privé. Il s’installe depuis GitHub, à une version précise :

```bash
bun add github:Enerlia/enerlia-auth-secure#v0.2.0
# ou
npm install github:Enerlia/enerlia-auth-secure#v0.2.0
```

Le build de l’app (CI, Dokploy) doit pouvoir lire ce dépôt privé, par exemple avec un jeton GitHub en lecture seule.

## Utilisation

```ts
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { securiteEnerlia, sessionEnerlia } from "enerlia-auth-secure";

export const auth = betterAuth({
  appName: "Nom de l’application", // refusé dans les mots de passe
  session: sessionEnerlia, // 48 h sans activité, prolongée au plus une fois par heure
  emailAndPassword: { enabled: true, minPasswordLength: 12, maxPasswordLength: 128 },
  // Limite de Better Auth : elle compte toutes les requêtes par adresse IP, réussies comme
  // échouées. La garder large pour ne pas bloquer un bureau entier derrière la même adresse.
  rateLimit: {
    enabled: true,
    storage: "database",
    customRules: {
      "/sign-in/email": { window: 60, max: 30 },
      "/two-factor/*": { window: 60, max: 30 },
    },
  },
  plugins: [
    ...securiteEnerlia(),
    twoFactor(),
  ],
});
```

Chaque plugin peut aussi être ajouté seul : `dureeSessionEnerlia()`, `tentativesEnerlia()`, `motDePasseEnerlia()`.

### Stockage du compteur de tentatives

Par défaut, `tentativesEnerlia` ajoute la table `enerliaTentative` à la base Better Auth. Il faut alors régénérer le schéma (`npx @better-auth/cli generate`, ou le schéma du composant Better Auth installé en local dans Convex).

Avec le composant `@convex-dev/better-auth` utilisé tel quel, on ne peut pas ajouter de table. Fournir alors un stockage qui écrit dans une table de l’app :

```ts
// convex/schema.ts
tentativesConnexion: defineTable({
  cle: v.string(),
  echecs: v.number(),
  dernierEchec: v.number(),
  bloqueJusqua: v.number(),
}).index("par_cle", ["cle"]),

// convex/auth.ts, dans createAuth(ctx)
tentativesEnerlia({
  stockage: {
    lire: (cle) => ctx.runQuery(internal.tentatives.lire, { cle }),
    ecrire: (cle, etat) => ctx.runMutation(internal.tentatives.ecrire, { cle, ...etat }),
    effacer: (cle) => ctx.runMutation(internal.tentatives.effacer, { cle }),
  },
}),
```

### Routes propres à l’app

`motDePasseEnerlia` contrôle les routes Better Auth où l’on choisit un mot de passe (inscription, changement, réinitialisation, création par un administrateur). Si l’app a ses propres routes, par exemple l’activation d’une invitation, il faut les déclarer :

```ts
motDePasseEnerlia({
  routesSupplementaires: [{ chemin: "/invitation/activate-password", champ: "password" }],
});
```

## Ce qui reste à la charge de l’app

- Garder la limite `rateLimit` de Better Auth large (30 requêtes par minute sur la connexion, par exemple). Réglée à 5, elle bloque tous les collègues d’un même bureau dès qu’un seul se trompe plusieurs fois.
- Transmettre la vraie adresse IP du visiteur derrière le proxy (Traefik, Dokploy) avec `advanced.ipAddress.ipAddressHeaders`. Sans adresse, Better Auth regroupe tous les visiteurs dans un seul compteur ; le compteur par IP de ce paquet, lui, ne s’applique simplement pas.
- Les règles du référentiel que ce paquet ne couvre pas encore : 2FA obligatoire côté serveur, réauthentification avant une action sensible, notifications par e-mail, en-têtes HTTP.
- Les mots de passe déjà enregistrés : les règles s’appliquent quand un mot de passe est choisi, pas à la connexion.

## Comportements à connaître

- **Session :** une session plus vieille que 7 jours est refusée à sa prochaine prolongation (au plus une heure après), puis l’utilisateur se reconnecte.
- **Tentatives :** les essais sur une adresse e-mail inconnue sont comptés comme les autres, pour ne pas révéler l’existence d’un compte. Un tiers qui connaît une adresse peut la faire bloquer 15 minutes ; la réinitialisation du mot de passe la débloque. Les collègues qui partagent la même connexion ne sont pas touchés : seuls 50 échecs en 15 minutes depuis la même adresse IP bloquent ce réseau, avec le message « Trop de tentatives échouées depuis votre réseau ».
- **Fuites :** seuls les 5 premiers caractères de l’empreinte SHA-1 sont envoyés à Pwned Passwords. Si le service ne répond pas, le mot de passe est accepté après le contrôle de la liste locale.

## Développement

```bash
bun install
bun run check   # types, tests, build
```

Le dossier `dist` est versionné pour l’installation depuis GitHub : relancer `bun run build` avant chaque commit qui modifie `src`. Publier une version : mettre à jour `version` dans `package.json`, puis créer le tag `vX.Y.Z`.
