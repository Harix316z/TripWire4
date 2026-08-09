// Hash family fingerprints: matched by exact length, charset, and structural
// prefixes. Ordered roughly by specificity so distinctive prefixes (bcrypt,
// argon2, PHC strings) are checked before generic hex-length fallbacks.

const HEX = /^[a-f0-9]+$/i;
const HEX_UPPER_OK = /^[A-Fa-f0-9]+$/;
const BASE64ISH = /^[A-Za-z0-9+/=_-]+$/;

function isHex(s) {
  return HEX_UPPER_OK.test(s);
}

const FAMILIES = [
  {
    id: "argon2",
    name: "Argon2 (i/d/id)",
    category: "PHC string / KDF",
    test: (s) => /^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/.test(s),
    confidence: "high",
    note: "PHC-formatted. Parameters (m, t, p) are embedded in the string itself.",
  },
  {
    id: "bcrypt",
    name: "bcrypt",
    category: "Adaptive hash",
    test: (s) => /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(s),
    confidence: "high",
    note: "60 chars, cost factor embedded after $2a/b/x/y$.",
  },
  {
    id: "scrypt",
    name: "scrypt (PHC string)",
    category: "Adaptive hash",
    test: (s) => /^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/.test(s),
    confidence: "high",
    note: "PHC-formatted scrypt with N/r/p cost parameters.",
  },
  {
    id: "phpass",
    name: "phpass / WordPress",
    category: "Salted hash",
    test: (s) => /^\$P\$[./A-Za-z0-9]{31}$/.test(s) || /^\$H\$[./A-Za-z0-9]{31}$/.test(s),
    confidence: "high",
    note: "Used by WordPress, phpBB3, and older PHP CMS platforms.",
  },
  {
    id: "django-pbkdf2",
    name: "Django PBKDF2-SHA256",
    category: "KDF",
    test: (s) => /^pbkdf2_sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/=]+$/.test(s),
    confidence: "high",
    note: "Django's default password hasher.",
  },
  {
    id: "unix-sha512crypt",
    name: "SHA-512 crypt (Unix)",
    category: "Unix shadow",
    test: (s) => /^\$6\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}$/.test(s),
    confidence: "high",
    note: "glibc crypt(3), found in /etc/shadow.",
  },
  {
    id: "unix-sha256crypt",
    name: "SHA-256 crypt (Unix)",
    category: "Unix shadow",
    test: (s) => /^\$5\$(rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}$/.test(s),
    confidence: "high",
    note: "glibc crypt(3), found in /etc/shadow.",
  },
  {
    id: "unix-md5crypt",
    name: "MD5 crypt (Unix)",
    category: "Unix shadow",
    test: (s) => /^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$/.test(s),
    confidence: "high",
    note: "Legacy Unix crypt(3). Considered weak.",
  },
  {
    id: "ntlm",
    name: "NTLM",
    category: "Windows",
    test: (s) => isHex(s) && s.length === 32,
    confidence: "low",
    note: "Same length/charset as MD5 and MD4 — context (source system) needed to confirm.",
    coFamily: ["md5", "md4"],
  },
  {
    id: "md5",
    name: "MD5",
    category: "Digest",
    test: (s) => isHex(s) && s.length === 32,
    confidence: "low",
    note: "128-bit digest. Broken for collision resistance; still common for checksums.",
    coFamily: ["ntlm", "md4"],
  },
  {
    id: "sha1",
    name: "SHA-1",
    category: "Digest",
    test: (s) => isHex(s) && s.length === 40,
    confidence: "medium",
    note: "160-bit digest. Deprecated for security use since 2017 (SHAttered).",
  },
  {
    id: "sha224",
    name: "SHA-224",
    category: "Digest",
    test: (s) => isHex(s) && s.length === 56,
    confidence: "medium",
    note: "224-bit SHA-2 variant.",
  },
  {
    id: "sha256",
    name: "SHA-256",
    category: "Digest",
    test: (s) => isHex(s) && s.length === 64,
    confidence: "medium",
    note: "256-bit digest. Also matches SHA3-256 and BLAKE2s-256 output length.",
    coFamily: ["sha3-256", "blake2s-256"],
  },
  {
    id: "sha384",
    name: "SHA-384",
    category: "Digest",
    test: (s) => isHex(s) && s.length === 96,
    confidence: "medium",
    note: "384-bit SHA-2 variant.",
  },
  {
    id: "sha512",
    name: "SHA-512",
    category: "Digest",
    test: (s) => isHex(s) && s.length === 128,
    confidence: "medium",
    note: "512-bit digest. Also matches SHA3-512 and BLAKE2b-512 output length.",
    coFamily: ["sha3-512", "blake2b-512"],
  },
  {
    id: "mysql41",
    name: "MySQL 4.1+ (SHA1-based)",
    category: "Application",
    test: (s) => /^\*[A-F0-9]{40}$/i.test(s),
    confidence: "high",
    note: "Leading asterisk followed by 40 hex chars.",
  },
  {
    id: "crc32",
    name: "CRC32",
    category: "Checksum",
    test: (s) => isHex(s) && s.length === 8,
    confidence: "low",
    note: "Non-cryptographic checksum, not a password hash.",
  },
  {
    id: "jwt",
    name: "JWT (JSON Web Token)",
    category: "Token",
    test: (s) => /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(s),
    confidence: "high",
    note: "Base64url header.payload.signature. Not a hash — decode to inspect claims.",
  },
];

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function identifyHash(raw) {
  const input = raw.trim();
  if (!input) return { input, matches: [], stats: null };

  const matches = FAMILIES.filter((f) => f.test(input)).map((f) => ({
    id: f.id,
    name: f.name,
    category: f.category,
    confidence: f.confidence,
    note: f.note,
    coFamily: f.coFamily || [],
  }));

  const stats = {
    length: input.length,
    charset: isHex(input)
      ? "hexadecimal"
      : BASE64ISH.test(input)
      ? "base64 / PHC-safe"
      : "mixed / punctuated",
    entropy: Number(shannonEntropy(input).toFixed(2)),
  };

  return { input, matches, stats };
}
