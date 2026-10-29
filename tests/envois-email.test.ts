import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { twoFactor } from "better-auth/plugins/two-factor";
import { afterEach, describe, expect, it, vi } from "vitest";
import { compterDemande, envoisEmailEnerlia } from "../src/envois-email";
import { tentativesEnerlia } from "../src/tentatives";
import { MDP, cookieDe, creerAuth, nouvelleBase, resultat } from "./aide";

const MIN = 60_000;

afterEach(() => {
  vi.useRealTimers();
});

describe("envois d'e-mails : calcul", () => {
  it("accepte 3 demandes sur 10 minutes, refuse la 4e, puis repart à la fenêtre suivante", () => {
    let etat = null;
    for (let i = 0; i < 3; i++) {
      const d = compterDemande(etat, 1000 + i);
      if (!d.accepte) throw new Error("refus inattendu");
      etat = d.etat;
    }
    expect(compterDemande(etat, 2000)).toEqual({ accepte: false, attenteMs: 1000 + 10 * MIN - 2000 });
    expect(compterDemande(etat, 1000 + 10 * MIN)).toMatchObject({ accepte: true, etat: { echecs: 1 } });
  });
});

describe("envois d'e-mails : mot de passe oublié, de bout en bout", () => {
  function preparer() {
    const envoyes: string[] = [];
    const auth = creerAuth(nouvelleBase(), {
      emailAndPassword: {
        sendResetPassword: async ({ user }: { user: { email: string } }) => {
          envoyes.push(user.email);
        },
      },
      plugins: [tentativesEnerlia(), envoisEmailEnerlia()],
    });
    const demander = (email: string) => () => auth.api.requestPasswordReset({ body: { email, redirectTo: "/nouveau" } });
    return { auth, envoyes, demander };
  }

  it("la 4e demande en 10 minutes pour la même adresse n'envoie pas d'e-mail", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-11-02T08:00:00Z") });
    const { auth, envoyes, demander } = preparer();
    await auth.api.signUpEmail({ body: { email: "alice@exemple.fr", password: MDP, name: "Alice" } });
    for (let i = 0; i < 3; i++) expect(await resultat(demander("alice@exemple.fr"))).toBe("ok");
    expect(await resultat(demander("Alice@Exemple.fr"))).toBe("429 TROP_DE_DEMANDES_EMAIL");
    expect(envoyes).toHaveLength(3);

    // Une autre adresse n'est pas gênée, et la limite se lève après 10 minutes.
    await auth.api.signUpEmail({ body: { email: "paul@exemple.fr", password: MDP, name: "Paul" } });
    expect(await resultat(demander("paul@exemple.fr"))).toBe("ok");
    vi.setSystemTime(new Date("2026-11-02T08:10:01Z"));
    expect(await resultat(demander("alice@exemple.fr"))).toBe("ok");
    expect(envoyes).toHaveLength(5);
  });

  it("répond de la même façon pour une adresse inconnue", async () => {
    const { demander } = preparer();
    for (let i = 0; i < 3; i++) expect(await resultat(demander("personne@exemple.fr"))).toBe("ok");
    expect(await resultat(demander("personne@exemple.fr"))).toBe("429 TROP_DE_DEMANDES_EMAIL");
  });
});

describe("envois d'e-mails : code 2FA par e-mail, de bout en bout", () => {
  it("limite l'envoi du code à 3 en 10 minutes pour un même compte", async () => {
    const base = nouvelleBase();
    let envoyes = 0;
    const authComplet = creerAuth(base, {
      plugins: [
        twoFactor({
          otpOptions: {
            sendOTP: async () => {
              envoyes++;
            },
          },
        }),
        envoisEmailEnerlia(),
      ],
    });
    // biome-ignore lint/suspicious/noExplicitAny: routes 2FA ajoutées par le plugin, non typées par l'aide de test
    const auth = authComplet as unknown as { api: Record<string, (...args: any[]) => Promise<any>> };
    const inscription = await auth.api.signUpEmail({ body: { email: "a@exemple.fr", password: MDP, name: "Alice" }, asResponse: true });
    const session = new Headers({ cookie: cookieDe(inscription) });
    const { totpURI } = (await auth.api.enableTwoFactor({ body: { password: MDP }, headers: session })) as { totpURI: string };
    const secret = new TextDecoder().decode(base32.decode(new URL(totpURI).searchParams.get("secret") ?? ""));
    await auth.api.verifyTOTP({ body: { code: await createOTP(secret, { digits: 6, period: 30 }).totp() }, headers: session });

    const etape = await auth.api.signInEmail({ body: { email: "a@exemple.fr", password: MDP }, asResponse: true });
    const deuxFacteurs = new Headers({ cookie: cookieDe(etape) });
    const envoyer = () => auth.api.sendTwoFactorOTP({ body: {}, headers: deuxFacteurs });
    for (let i = 0; i < 3; i++) expect(await resultat(envoyer)).toBe("ok");
    expect(await resultat(envoyer)).toBe("429 TROP_DE_DEMANDES_EMAIL");
    expect(envoyes).toBe(3);
  });
});
