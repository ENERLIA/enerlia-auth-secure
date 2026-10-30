import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { twoFactor } from "better-auth/plugins/two-factor";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { controleConnexionEnerlia, estMotDePasseCompromis, type ResultatControle } from "../src/controle-connexion";
import { cookieDe, creerAuth, nouvelleBase } from "./aide";

const FAIBLE = "soleil2024"; // 10 caractères, enregistré avant les règles actuelles
const SOLIDE = "une phrase assez longue";

// Service de fuites simulé : aucun mot de passe n'y figure, sauf ceux de `fuites`.
let fuites: string[] = [];
async function sha1(texte: string) {
  const o = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(texte)));
  return Array.from(o, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
}
beforeEach(() => {
  fuites = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response((await Promise.all(fuites.map(sha1))).map((h) => `${h.slice(5)}:3`).join("\n"))),
  );
});
afterEach(() => vi.unstubAllGlobals());

function preparer(options: { estControle?: boolean; deuxFacteurs?: boolean } = {}) {
  const resultats: ResultatControle[] = [];
  const controles = new Set<string>();
  const base = nouvelleBase();
  const plugin = controleConnexionEnerlia({
    enregistrer: async (r) => {
      resultats.push(r);
      controles.add(r.userId);
    },
    ...(options.estControle === false ? {} : { estControle: async (id: string) => controles.has(id) }),
  });
  const authComplet = creerAuth(base, {
    emailAndPassword: { minPasswordLength: 8 },
    plugins: options.deuxFacteurs ? [plugin, twoFactor()] : [plugin],
  });
  // biome-ignore lint/suspicious/noExplicitAny: routes ajoutées par les plugins, non typées par l'aide de test
  const auth = authComplet as unknown as { api: Record<string, (...args: any[]) => Promise<any>> };
  return { auth, base, resultats, controles };
}

async function inscrire(auth: ReturnType<typeof preparer>["auth"], password: string) {
  const reponse = await auth.api.signUpEmail({ body: { email: "a@exemple.fr", password, name: "Alice" }, asResponse: true });
  return new Headers({ cookie: cookieDe(reponse) });
}
const connecter = (auth: ReturnType<typeof preparer>["auth"], password: string) =>
  auth.api.signInEmail({ body: { email: "a@exemple.fr", password }, asResponse: true });

describe("contrôle à la connexion", () => {
  it("signale un mot de passe trop court, sans bloquer la connexion", async () => {
    const { auth, resultats } = preparer();
    await inscrire(auth, FAIBLE);
    const reponse = await connecter(auth, FAIBLE);
    expect(reponse.status).toBe(200);
    expect(resultats).toEqual([{ userId: expect.any(String), conforme: false }]);
  });

  it("signale un mot de passe présent dans une fuite connue", async () => {
    const { auth, resultats } = preparer();
    await inscrire(auth, SOLIDE);
    fuites = [SOLIDE];
    await connecter(auth, SOLIDE);
    expect(resultats.at(-1)?.conforme).toBe(false);
  });

  it("valide un mot de passe conforme", async () => {
    const { auth, resultats } = preparer();
    await inscrire(auth, SOLIDE);
    await connecter(auth, SOLIDE);
    expect(resultats.at(-1)?.conforme).toBe(true);
  });

  it("ne contrôle rien sur un mauvais mot de passe", async () => {
    const { auth, resultats } = preparer();
    await inscrire(auth, SOLIDE);
    expect((await connecter(auth, "pas le bon mot de passe")).status).toBe(401);
    expect(resultats).toEqual([]);
  });

  it("contrôle aussi quand la double authentification attend son code", async () => {
    const { auth, resultats } = preparer({ deuxFacteurs: true });
    const session = await inscrire(auth, FAIBLE);
    const { totpURI } = await auth.api.enableTwoFactor({ body: { password: FAIBLE }, headers: session });
    const secret = new TextDecoder().decode(base32.decode(new URL(totpURI).searchParams.get("secret") ?? ""));
    await auth.api.verifyTOTP({ body: { code: await createOTP(secret, { digits: 6, period: 30 }).totp() }, headers: session });
    const reponse = await connecter(auth, FAIBLE);
    expect(await reponse.json()).toMatchObject({ twoFactorRedirect: true });
    expect(resultats.at(-1)).toEqual({ userId: expect.any(String), conforme: false });
  });

  it("valide le nouveau mot de passe choisi par un utilisateur connecté", async () => {
    const { auth, resultats } = preparer();
    await inscrire(auth, FAIBLE);
    const session = new Headers({ cookie: cookieDe(await connecter(auth, FAIBLE)) });
    await auth.api.changePassword({ body: { currentPassword: FAIBLE, newPassword: SOLIDE }, headers: session });
    expect(resultats.map((r) => r.conforme)).toEqual([false, true]);
  });
});

describe("déconnexion des comptes jamais contrôlés", () => {
  it("ferme la session d'un utilisateur dont le mot de passe n'a jamais été contrôlé", async () => {
    const { auth, base } = preparer();
    const session = await inscrire(auth, SOLIDE); // session ouverte sans contrôle (avant la mise en place)
    expect(await auth.api.getSession({ headers: session })).toBeNull();
    expect(base.session).toHaveLength(0);
    await expect(auth.api.getSession({ headers: session })).resolves.toBeNull();
  });

  it("garde la session après une connexion contrôlée, même si le mot de passe est à changer", async () => {
    const { auth } = preparer();
    await inscrire(auth, FAIBLE);
    const session = new Headers({ cookie: cookieDe(await connecter(auth, FAIBLE)) });
    expect((await auth.api.getSession({ headers: session }))?.user.email).toBe("a@exemple.fr");
  });

  it("ne coupe rien sans fonction estControle", async () => {
    const { auth } = preparer({ estControle: false });
    const session = await inscrire(auth, SOLIDE);
    expect((await auth.api.getSession({ headers: session }))?.user.email).toBe("a@exemple.fr");
  });
});

describe("service de fuites", () => {
  it("répond « non » si le service ne répond pas", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("réseau coupé"); }));
    expect(await estMotDePasseCompromis(SOLIDE)).toBe(false);
  });
});
