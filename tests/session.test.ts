import { describe, expect, it } from "vitest";
import {
  SESSION_DUREE_MAX_MS,
  dureeSessionEnerlia,
  limiterDureeSession,
  plafonnerExpiration,
  sessionEnerlia,
} from "../src/session";
import { MDP, cookieDe, creerAuth, nouvelleBase } from "./aide";

const HEURE = 3600_000;
const JOUR = 24 * HEURE;

describe("durée des sessions : calcul", () => {
  const maintenant = Date.UTC(2026, 9, 28, 12);
  it("garde 48 h d'inactivité, prolongées au plus une fois par heure", () => {
    expect(sessionEnerlia).toEqual({ expiresIn: 48 * 3600, updateAge: 3600 });
    expect(SESSION_DUREE_MAX_MS).toBe(7 * JOUR);
  });
  it("laisse passer, plafonne puis refuse", () => {
    expect(plafonnerExpiration(new Date(maintenant + 48 * HEURE), new Date(maintenant - 2 * JOUR), maintenant)).toBeUndefined();
    expect(plafonnerExpiration(new Date(maintenant + 48 * HEURE), new Date(maintenant - 6 * JOUR), maintenant)).toEqual({
      data: { expiresAt: new Date(maintenant + JOUR) },
    });
    expect(plafonnerExpiration(new Date(maintenant + 48 * HEURE), new Date(maintenant - 7 * JOUR), maintenant)).toBe(false);
  });
  it("ignore une mise à jour sans expiration ou sans session connue", async () => {
    expect(await limiterDureeSession({}, { context: { session: { session: { createdAt: new Date() } } } })).toBeUndefined();
    expect(await limiterDureeSession({ expiresAt: new Date() }, null)).toBeUndefined();
  });
});

describe("durée des sessions : de bout en bout avec Better Auth", () => {
  it("48 h après la connexion, plafond à 7 jours, refus au-delà", async () => {
    const base = nouvelleBase();
    const auth = creerAuth(base, { session: sessionEnerlia, plugins: [dureeSessionEnerlia()] });
    const rep = await auth.api.signUpEmail({ body: { email: "a@exemple.fr", password: MDP, name: "Alice" }, asResponse: true });
    const headers = new Headers({ cookie: cookieDe(rep) });
    const s = base.session[0];
    const heuresRestantes = () => (s.expiresAt.getTime() - Date.now()) / HEURE;
    expect(heuresRestantes()).toBeCloseTo(48, 0);

    s.createdAt = new Date(Date.now() - 6.5 * JOUR);
    s.expiresAt = new Date(Date.now() + 46 * HEURE);
    expect(await auth.api.getSession({ headers })).not.toBeNull();
    expect(heuresRestantes()).toBeCloseTo(12, 0);

    s.createdAt = new Date(Date.now() - 8 * JOUR);
    s.expiresAt = new Date(Date.now() + 46 * HEURE);
    await expect(auth.api.getSession({ headers })).rejects.toMatchObject({ statusCode: 401 });
  });
});
