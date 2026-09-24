// Runs the crypto code taken straight from index.html against published known-answer vectors
// and against values produced by the Mule secure-properties library itself (test/vectors.json).
// Usage: node test/test.js
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "..", "index.html"), "utf8");
const code = html.slice(html.indexOf("// CRYPTO-START"), html.indexOf("// CRYPTO-END"));
const MuleSecure = new Function(code + "\nreturn MuleSecure;")();
const T = MuleSecure._test;

const hex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
const toHex = b => Buffer.from(b).toString("hex");
let fail = 0, checks = 0;
const check = (name, cond) => { checks++; if (!cond) { fail++; console.log("FAIL", name); } };

// Known-answer tests: AES (FIPS-197 appendix C), DES, Blowfish (Schneier's test vectors)
check("AES S-box", T.SBOX[0] === 0x63 && T.SBOX[1] === 0x7c && T.SBOX[0x53] === 0xed && T.SBOX[0xff] === 0x16);
const aesPlain = hex("00112233445566778899aabbccddeeff");
for (const [key, cipher] of [["000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"],
                             ["000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"],
                             ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"]]) {
  const c = T.aes(hex(key));
  check("FIPS-197 AES-" + key.length * 4, toHex(c.encrypt(aesPlain)) === cipher && toHex(c.decrypt(hex(cipher))) === toHex(aesPlain));
}
const des = T.des(hex("133457799bbcdff1"));
check("DES known answer", toHex(des.encrypt(hex("0123456789abcdef"))) === "85e813540f0ab405"
                          && toHex(des.decrypt(hex("85e813540f0ab405"))) === "0123456789abcdef");
const bf0 = T.blowfish(hex("0000000000000000"));
check("Blowfish known answer (zero key)", toHex(bf0.encrypt(hex("0000000000000000"))) === "4ef997456198dd78"
                                           && toHex(bf0.decrypt(hex("4ef997456198dd78"))) === "0000000000000000");
const bf1 = T.blowfish(hex("ffffffffffffffff"));
check("Blowfish known answer (ff key)", toHex(bf1.encrypt(hex("ffffffffffffffff"))) === "51866fd5b85ecb8a");

// Values produced by the Mule library for every algorithm and mode
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, "vectors.json"), "utf8"));
const perMode = {};
for (const v of vectors) {
  const tag = v.alg + "/" + v.mode + " key(" + v.key.length + ") \"" + v.value + "\"";
  perMode[v.alg + "/" + v.mode] = (perMode[v.alg + "/" + v.mode] || 0) + 1;
  let enc, dec;
  try { enc = MuleSecure.encrypt(v.value, v.key, v.alg, v.mode); } catch (e) { enc = "ERROR " + e.message; }
  try { dec = MuleSecure.decrypt('  password: "' + v.enc + '"', v.key, v.alg, v.mode); } catch (e) { dec = "ERROR " + e.message; }
  check("encrypt matches Mule: " + tag + " got " + enc + " expected " + v.enc, enc === v.enc);
  check("decrypt Mule value: " + tag + " got " + dec, dec === v.value);
}

// A wrong key or a wrong mode never gives the original value back
let rejected = 0, attempts = 0;
for (const v of vectors) {
  const otherKey = { AES: "ffffffffffffffff", DES: "ffffffff", DESede: "ffffffffffffffffffffffff", Blowfish: "wrongkey" }[v.alg];
  for (const [key, mode] of [[otherKey, v.mode], [v.key, v.mode === "CBC" ? "ECB" : "CBC"]]) {
    attempts++;
    try { if (MuleSecure.decrypt(v.enc, key, v.alg, mode) !== v.value) rejected++; } catch (e) { rejected++; }
  }
}
check("wrong key or mode never yields the value (" + rejected + "/" + attempts + ")", rejected === attempts);

// Key length rules, identical to the Mule library for lengths 1 to 60
const sizes = { AES: [16, 24, 32], DES: [8], DESede: [24] };
for (const alg of ["AES", "Blowfish", "DES", "DESede"]) {
  for (let n = 1; n <= 60; n++) {
    const expected = alg === "Blowfish" ? n <= 56 : sizes[alg].includes(n);
    check("key length " + alg + " " + n, MuleSecure.keyFits(n, alg) === expected);
  }
}

console.log(fail ? fail + " of " + checks + " checks FAILED"
                 : "All " + checks + " checks passed: " + vectors.length + " Mule vectors " + JSON.stringify(perMode));
process.exit(fail ? 1 : 0);
