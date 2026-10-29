import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { twoFactor } from "better-auth/plugins/two-factor";
import { describe, expect, it } from "vitest";
import {
  apresEchec,
  apresEchecIp,
  attenteIp,
  delaiAvantEssai,
  refusAvantEssai,
  stockageMemoire,
  tentativesEnerlia,
} from "../src/tentatives";
import { MDP, cookieDe, creerAuth, nouvelleBase, resultat } from "./aide";

const MIN = 60_000;

// biome-ignore lint/suspicious/noExplicitAny: ligne de la base en mémoire
function compteDe(base: Record<string, any[]>, email: string) {
  const ligne = base.enerliaTentative.find((t) => t.cle === `mdp:${email}`);
  if (!ligne) throw new Error(`aucun compteur pour ${email}`);
  return ligne;
}

describe("tentatives : calcul", () => {
  it("impose un délai croissant à partir du 3e échec, plafonné à 30 s", () => {
    expect([1, 2, 3, 4, 5, 9].map((n) => delaiAvantEssai(n))).toEqual([0, 0, 1000, 2000, 4000, 30_000]);
  });
  it("bloque 15 minutes au 10e échec consécutif", () => {
    let etat = null;
    for (let i = 0; i < 9; i++) etat = apresEchec(etat, 1000);
    expect(etat).toMatchObject({ echecs: 9, bloqueJusqua: 0 });
    expect(apresEchec(etat, 1000)).toMatchObject({ echecs: 10, bloqueJusqua: 1000 + 15 * MIN });
  });
  it("repart de zéro après la fin du blocage ou 24 h sans échec", () => {
    expect(apresEchec({ echecs: 10, dernierEchec: 0, bloqueJusqua: 15 * MIN }, 16 * MIN).echecs).toBe(1);
    expect(apresEchec({ echecs: 5, dernierEchec: 0, bloqueJusqua: 0 }, 25 * 60 * MIN).echecs).toBe(1);
  });
  it("refuse pendant le blocage et pendant le délai", () => {
    expect(refusAvantEssai({ echecs: 10, dernierEchec: 0, bloqueJusqua: 10 }, 5)?.raison).toBe("bloque");
    expect(refusAvantEssai({ echecs: 4, dernierEchec: 1000, bloqueJusqua: 0 }, 2000)?.raison).toBe("delai");
    expect(refusAvantEssai({ echecs: 4, dernierEchec: 1000, bloqueJusqua: 0 }, 3500)).toBeNull();
  });
  it("compte les échecs par IP sur une fenêtre fixe de 15 minutes", () => {
    let etat = null;
    for (let i = 0; i < 50; i++) etat = apresEchecIp(etat, 1000 + i);
    expect(attenteIp(etat, 2000)).toBe(1000 + 15 * MIN - 2000);
    expect(attenteIp(etat, 1000 + 15 * MIN)).toBe(0);
    expect(apresEchecIp(etat, 1000 + 15 * MIN).echecs).toBe(1);
  });
});

describe("tentatives : mot de passe, de bout en bout", () => {
  const connexion = (auth: ReturnType<typeof creerAuth>, email: string, password: string, ip = "203.0.113.10") => () =>
    auth.api.signInEmail({ body: { email, password }, headers: new Headers({ "x-forwarded-for": ip }) });

  it("délai croissant dès le 3e échec, puis essai accepté une fois le délai passé", async () => {
    const base = nouvelleBase();
    const auth = creerAuth(base, { plugins: [tentativesEnerlia()] });
    await auth.api.signUpEmail({ body: { email: "a@exemple.fr", password: MDP, name: "Alice" } });
    for (let i = 0; i < 3; i++) expect(await resultat(connexion(auth, "a@exemple.fr", "mauvais mot de passe"))).toBe("401 INVALID_EMAIL_OR_PASSWORD");
    expect(await resultat(connexion(auth, "a@exemple.fr", MDP))).toBe("429 TENTATIVE_TROP_RAPIDE");
    compteDe(base, "a@exemple.fr").dernierEchec -= 2000;
    expect(await resultat(connexion(auth, "a@exemple.fr", MDP))).toBe("ok");
    expect(base.enerliaTentative.some((t) => t.cle === "mdp:a@exemple.fr")).toBe(false);
  });

  it("bloque le compte après 10 échecs, même avec le bon mot de passe, puis le libère après 15 min", async () => {
    const base = nouvelleBase();
    const auth = creerAuth(base, { plugins: [tentativesEnerlia({ delaiInitialMs: 0 })] });
    await auth.api.signUpEmail({ body: { email: "a@exemple.fr", password: MDP, name: "Alice" } });
    for (let i = 0; i < 10; i++)
      expect(await resultat(connexion(auth, "A@Exemple.fr", "mauvais mot de passe"))).toBe("401 INVALID_EMAIL_OR_PASSWORD");
    expect(await resultat(connexion(auth, "a@exemple.fr", MDP))).toBe("429 COMPTE_TEMPORAIREMENT_BLOQUE");
    compteDe(base, "a@exemple.fr").bloqueJusqua = Date.now() - 1;
    expect(await resultat(connexion(auth, "a@exemple.fr", MDP))).toBe("ok");
  });

  it("traite une adresse inconnue comme les autres", async () => {
    const auth = creerAuth(nouvelleBase(), { plugins: [tentativesEnerlia({ delaiInitialMs: 0 })] });
    for (let i = 0; i < 10; i++) expect(await resultat(connexion(auth, "inconnu@exemple.fr", MDP))).toBe("401 INVALID_EMAIL_OR_PASSWORD");
    expect(await resultat(connexion(auth, "inconnu@exemple.fr", MDP))).toBe("429 COMPTE_TEMPORAIREMENT_BLOQUE");
  });

  it("un lien de réinitialisation valide débloque le compte", async () => {
    const base = nouvelleBase();
    let lien = "";
    const auth = creerAuth(base, {
      emailAndPassword: { sendResetPassword: async ({ token }: { token: string }) => { lien = token; } },
      plugins: [tentativesEnerlia({ delaiInitialMs: 0 })],
    });
    await auth.api.signUpEmail({ body: { email: "a@exemple.fr", password: MDP, name: "Alice" } });
    for (let i = 0; i < 10; i++) await resultat(connexion(auth, "a@exemple.fr", "mauvais mot de passe"));
    await auth.api.requestPasswordReset({ body: { email: "a@exemple.fr", redirectTo: "/" } });
    await auth.api.resetPassword({ body: { token: lien, newPassword: "un tout nouveau secret" } });
    expect(await resultat(connexion(auth, "a@exemple.fr", "un tout nouveau secret"))).toBe("ok");
  });

  it("accepte un stockage fourni par l'application", async () => {
    const stockage = stockageMemoire();
    const auth = creerAuth(nouvelleBase(), { plugins: [tentativesEnerlia({ stockage })] });
    await resultat(connexion(auth, "b@exemple.fr", MDP));
    expect(stockage.donnees.get("mdp:b@exemple.fr")?.echecs).toBe(1);
  });

  it("le blocage d'un compte ne gêne pas un collègue derrière la même adresse IP", async () => {
    const auth = creerAuth(nouvelleBase(), { plugins: [tentativesEnerlia({ delaiInitialMs: 0 })] });
    await auth.api.signUpEmail({ body: { email: "max@exemple.fr", password: MDP, name: "Max" } });
    await auth.api.signUpEmail({ body: { email: "collegue@exemple.fr", password: MDP, name: "Paul" } });
    for (let i = 0; i < 10; i++) await resultat(connexion(auth, "max@exemple.fr", "mauvais mot de passe", "198.51.100.7"));
    expect(await resultat(connexion(auth, "max@exemple.fr", MDP, "198.51.100.7"))).toBe("429 COMPTE_TEMPORAIREMENT_BLOQUE");
    expect(await resultat(connexion(auth, "collegue@exemple.fr", MDP, "198.51.100.7"))).toBe("ok");
  });

  it("bloque une adresse IP après 50 échecs sur des comptes différents, sans toucher les autres adresses", async () => {
    const auth = creerAuth(nouvelleBase(), { plugins: [tentativesEnerlia({ delaiInitialMs: 0 })] });
    await auth.api.signUpEmail({ body: { email: "alice@exemple.fr", password: MDP, name: "Alice" } });
    for (let i = 0; i < 50; i++)
      expect(await resultat(connexion(auth, `cible${i}@exemple.fr`, "motdepasse123", "192.0.2.66"))).toBe("401 INVALID_EMAIL_OR_PASSWORD");
    expect(await resultat(connexion(auth, "alice@exemple.fr", MDP, "192.0.2.66"))).toBe("429 TROP_D_ECHECS_DEPUIS_CE_RESEAU");
    expect(await resultat(connexion(auth, "alice@exemple.fr", MDP, "192.0.2.99"))).toBe("ok");
  });

  it("une connexion réussie ne compte pas comme un échec pour l'adresse IP", async () => {
    const stockage = stockageMemoire();
    const auth = creerAuth(nouvelleBase(), { plugins: [tentativesEnerlia({ stockage })] });
    await auth.api.signUpEmail({ body: { email: "alice@exemple.fr", password: MDP, name: "Alice" } });
    for (let i = 0; i < 60; i++) expect(await resultat(connexion(auth, "alice@exemple.fr", MDP, "192.0.2.10"))).toBe("ok");
    expect(stockage.donnees.has("ip:192.0.2.10")).toBe(false);
  });

  it("ne regroupe jamais les visiteurs dont l'adresse IP est inconnue", async () => {
    const stockage = stockageMemoire();
    const auth = creerAuth(nouvelleBase(), {
      advanced: { ipAddress: { disableIpTracking: true } },
      plugins: [tentativesEnerlia({ stockage })],
    });
    await resultat(connexion(auth, "inconnu@exemple.fr", MDP));
    expect([...stockage.donnees.keys()]).toEqual(["mdp:inconnu@exemple.fr"]);
  });
});

describe("tentatives : codes 2FA, de bout en bout", () => {
  it("bloque la saisie des codes après 10 codes faux, même en recommençant la connexion", async () => {
    const base = nouvelleBase();
    const authComplet = creerAuth(base, {
      plugins: [twoFactor({ accountLockout: { enabled: false } } as never), tentativesEnerlia({ delaiInitialMs: 0 })],
    });
    // biome-ignore lint/suspicious/noExplicitAny: routes 2FA ajoutées par le plugin, non typées par l'aide de test
    const auth = authComplet as unknown as { api: Record<string, (...args: any[]) => Promise<any>> };
    const inscription = await auth.api.signUpEmail({ body: { email: "a@exemple.fr", password: MDP, name: "Alice" }, asResponse: true });
    const session = new Headers({ cookie: cookieDe(inscription) });
    const { totpURI } = (await auth.api.enableTwoFactor({ body: { password: MDP }, headers: session })) as { totpURI: string };
    const secret = new TextDecoder().decode(base32.decode(new URL(totpURI).searchParams.get("secret") ?? ""));
    const code = () => createOTP(secret, { digits: 6, period: 30 }).totp();
    await auth.api.verifyTOTP({ body: { code: await code() }, headers: session });

    const etapeMotDePasse = async () => {
      const etape = await auth.api.signInEmail({ body: { email: "a@exemple.fr", password: MDP }, asResponse: true });
      expect(await etape.clone().json()).toMatchObject({ twoFactorRedirect: true });
      return new Headers({ cookie: cookieDe(etape) });
    };
    // Better Auth limite aussi les essais par étape de connexion : l'attaquant recommence alors la connexion.
    let deuxFacteurs = await etapeMotDePasse();
    let codesFaux = 0;
    while (codesFaux < 10) {
      const r = await resultat(() => auth.api.verifyTOTP({ body: { code: "000000" }, headers: deuxFacteurs }));
      if (r === "401 INVALID_CODE") codesFaux++;
      else if (r.endsWith("TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE")) deuxFacteurs = await etapeMotDePasse();
      else throw new Error(`réponse inattendue : ${r}`);
    }
    deuxFacteurs = await etapeMotDePasse();
    expect(await resultat(async () => auth.api.verifyTOTP({ body: { code: await code() }, headers: deuxFacteurs }))).toBe(
      "429 COMPTE_TEMPORAIREMENT_BLOQUE",
    );
    expect(base.enerliaTentative.some((t) => String(t.cle).startsWith("2fa:"))).toBe(true);
  });
});
