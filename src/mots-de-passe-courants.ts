/**
 * Mots de passe courants refusés même quand le service Pwned Passwords ne
 * répond pas. La liste vise les mots de passe d'au moins 12 caractères (les
 * plus courts sont déjà refusés par la longueur) ; les suites et répétitions
 * sont détectées à part dans `estMotDePasseCourant`.
 */
export const MOTS_DE_PASSE_COURANTS: readonly string[] = [
  "motdepasse123", "motdepasse1234", "motdepasse2024", "motdepasse2025", "motdepasse2026",
  "monmotdepasse", "monmotdepasse1", "monmotdepasse123", "motdepassesecret", "motdepassesecure",
  "password1234", "password12345", "password123456", "passwordpassword", "mypassword123",
  "azertyuiop123", "azertyuiop1234", "azertyuiopqsdf", "azertyuiopqsdfghjklm", "azerty123456",
  "azerty1234567", "azertyazerty", "qwertyuiop123", "qwertyuiop1234", "qwerty123456",
  "qwertyqwerty", "qwertyuiopasdf", "1q2w3e4r5t6y", "1q2w3e4r5t6y7u", "1a2z3e4r5t6y",
  "iloveyou1234", "jetaime123456", "jetaimetoujours", "bonjour123456", "soleil123456",
  "doudou123456", "chouchou1234", "loulou123456", "marseille13013", "liverpool1234",
  "football1234", "football12345", "baseball1234", "superman1234", "batman123456",
  "welcome12345", "welcome123456", "bienvenue123", "bienvenue1234", "administrateur",
  "administrator", "admin1234567", "adminadmin123", "changeme1234", "changezmoi123",
  "letmein12345", "trustno11234", "starwars1234", "princesse123", "nicolas12345",
  "abcdefgh1234", "abc123456789", "123456789abc", "1234567890ab", "123456789azerty",
  "0123456789ab", "aaaaaa123456", "1234qwerasdf", "1234azerqsdf", "zaq12wsxcde3",
  "1qaz2wsx3edc", "qazwsxedcrfv", "passw0rd1234", "p@ssw0rd1234", "p@ssword1234",
  "m0td3p4ss3123", "motdepasse!!", "motdepasse123!", "azerty123456!", "password1234!",
];

const SUITES = [
  "0123456789012345678901234567890",
  "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
  "azertyuiopqsdfghjklmwxcvbn",
  "qwertyuiopasdfghjklzxcvbnm",
];

/** Vrai pour un mot de passe de la liste, une répétition ou une simple suite de clavier. */
export function estMotDePasseCourant(motDePasse: string, liste: readonly string[] = MOTS_DE_PASSE_COURANTS): boolean {
  const simple = motDePasse.toLowerCase();
  if (liste.includes(simple)) return true;
  if (/^(.{1,4})\1+$/u.test(simple)) return true;
  for (const suite of SUITES) {
    const inverse = [...suite].reverse().join("");
    if (suite.includes(simple) || inverse.includes(simple)) return true;
  }
  return false;
}
