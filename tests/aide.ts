import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";

// biome-ignore lint/suspicious/noExplicitAny: base en mémoire des tests
export type Base = Record<string, any[]>;

export function nouvelleBase(): Base {
  return { user: [], session: [], account: [], verification: [], twoFactor: [], enerliaTentative: [] };
}

export const MDP = "une phrase assez longue";

// biome-ignore lint/suspicious/noExplicitAny: options libres selon le test
export function creerAuth(base: Base, options: Record<string, any> = {}) {
  const { emailAndPassword, ...autres } = options;
  return betterAuth({
    appName: "Application Test",
    secret: "secret-de-test-suffisamment-long-et-aleatoire-0123456789",
    baseURL: "http://localhost:3000",
    database: memoryAdapter(base),
    logger: { disabled: true },
    rateLimit: { enabled: false },
    ...autres,
    emailAndPassword: { enabled: true, ...(emailAndPassword ?? {}) },
  });
}

export function cookieDe(reponse: Response): string {
  return (reponse.headers.getSetCookie?.() ?? [reponse.headers.get("set-cookie") ?? ""])
    .map((c) => c.split(";")[0])
    .filter(Boolean)
    .join("; ");
}

/** Statut et code d'une erreur Better Auth, ou "ok". */
export async function resultat(appel: () => Promise<unknown>): Promise<string> {
  try {
    await appel();
    return "ok";
  } catch (e) {
    // biome-ignore lint/suspicious/noExplicitAny: erreur Better Auth
    const err = e as any;
    return `${err.statusCode ?? err.status} ${err.body?.code ?? err.message}`;
  }
}
