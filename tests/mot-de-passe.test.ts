import { afterEach, describe, expect, it, vi } from "vitest";
import { motDePasseEnerlia, verifierMotDePasse } from "../src/mot-de-passe";
import { creerAuth, nouvelleBase, resultat } from "./aide";

async function sha1(texte: string) {
  const empreinte = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(texte));
  return [...new Uint8Array(empreinte)].map((o) => o.toString(16).padStart(2, "0")).join("").toUpperCase();
}

/** Simule Pwned Passwords : "fuites" contient les mots de passe compromis, "panne" coupe le service. */
function simulerPwned(fuites: string[] = [], panne = false) {
  const appels: string[] = [];
  vi.stubGlobal("fetch", async (url: string) => {
    appels.push(String(url));
    if (panne) throw new Error("réseau indisponible");
    const prefixe = String(url).split("/").pop() ?? "";
    const lignes = (await Promise.all(fuites.map(sha1))).filter((h) => h.startsWith(prefixe)).map((h) => `${h.slice(5)}:12`);
    return new Response([...lignes, "0000000000000000000000000000000000A:0"].join("\n"), { status: 200 });
  });
  return appels;
}

afterEach(() => vi.unstubAllGlobals());

describe("règles de mot de passe : contrôles locaux", () => {
  const infos = { email: "alice.martin@exemple.fr", nom: "Alice Martin", application: "Adeho Solutions" };
  it.each([
    ["treizelettres", "MOT_DE_PASSE_TROP_COURT"],
    ["x".repeat(129), "MOT_DE_PASSE_TROP_LONG"],
    ["un soleil radieux 🌞 ici", "MOT_DE_PASSE_EMOJI"],
    ["motdepasse1234", "MOT_DE_PASSE_COURANT"],
    ["azertyuiopqsdf", "MOT_DE_PASSE_COURANT"],
    ["ababababababab", "MOT_DE_PASSE_COURANT"],
    ["martin et son chien", "MOT_DE_PASSE_PERSONNEL"],
    ["alice.martin2026!", "MOT_DE_PASSE_PERSONNEL"],
    ["j'aime adeho depuis toujours", "MOT_DE_PASSE_PERSONNEL"],
  ])("refuse « %s »", (mdp, code) => {
    expect(verifierMotDePasse(mdp, infos)).toBe(code);
  });
  it("accepte 14 minuscules sans règle de composition, et les accents", () => {
    expect(verifierMotDePasse("cheval agrafeur", infos)).toBeNull();
    expect(verifierMotDePasse("été à la campagne", infos)).toBeNull();
  });
});

describe("règles de mot de passe : de bout en bout avec Better Auth", () => {
  const inscrire = (auth: ReturnType<typeof creerAuth>, password: string, email = "alice@exemple.fr") => () =>
    auth.api.signUpEmail({ body: { email, password, name: "Alice Martin" } });

  it("applique les règles locales à l'inscription", async () => {
    simulerPwned();
    const auth = creerAuth(nouvelleBase(), { plugins: [motDePasseEnerlia()] });
    expect(await resultat(inscrire(auth, "trop court"))).toBe("400 MOT_DE_PASSE_TROP_COURT");
    expect(await resultat(inscrire(auth, "martin pour toujours"))).toBe("400 MOT_DE_PASSE_PERSONNEL");
    expect(await resultat(inscrire(auth, "application test 2026"))).toBe("400 MOT_DE_PASSE_PERSONNEL");
    expect(await resultat(inscrire(auth, "cheval agrafeur"))).toBe("ok");
  });

  it("refuse un mot de passe présent dans une fuite connue, sans l'envoyer en clair", async () => {
    const appels = simulerPwned(["fuite tres connue"]);
    const auth = creerAuth(nouvelleBase(), { plugins: [motDePasseEnerlia()] });
    expect(await resultat(inscrire(auth, "fuite tres connue"))).toBe("400 PASSWORD_COMPROMISED");
    expect(appels[0]).toMatch(/\/range\/[0-9A-F]{5}$/);
  });

  it("accepte quand le service Pwned Passwords est indisponible (liste locale appliquée)", async () => {
    simulerPwned([], true);
    const auth = creerAuth(nouvelleBase(), { plugins: [motDePasseEnerlia()] });
    expect(await resultat(inscrire(auth, "motdepasse1234"))).toBe("400 MOT_DE_PASSE_COURANT");
    expect(await resultat(inscrire(auth, "cheval agrafeur"))).toBe("ok");
  });

  it("reconnaît un mot de passe accentué saisi sous une autre forme Unicode", async () => {
    simulerPwned();
    const auth = creerAuth(nouvelleBase(), { plugins: [motDePasseEnerlia()] });
    const nfd = "été à la campagne".normalize("NFD");
    expect(await resultat(inscrire(auth, nfd))).toBe("ok");
    expect(await resultat(() => auth.api.signInEmail({ body: { email: "alice@exemple.fr", password: nfd.normalize("NFC") } }))).toBe("ok");
  });

  it("contrôle aussi une route propre à l'application", async () => {
    simulerPwned();
    const auth = creerAuth(nouvelleBase(), {
      plugins: [motDePasseEnerlia({ routesSupplementaires: [{ chemin: "/sign-up/email", champ: "password" }], verifierFuites: false })],
    });
    expect(await resultat(inscrire(auth, "trop court"))).toBe("400 MOT_DE_PASSE_TROP_COURT");
  });
});
