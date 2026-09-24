# mulesoft-secure-properties

Encrypt and decrypt MuleSoft secure properties (`![...]` values) in your browser. One HTML file: no install, no
dependencies, works offline.

**Use it online:** https://mysticalhand.github.io/mulesoft-secure-properties/

It produces exactly what Mule's `<secure-properties:config>` reads, so you can:

- encrypt a new password, token, or client secret and paste it into your `secure-*.yaml`;
- decrypt a value to see what the application actually uses;
- check that you have the right key. Encryption is deterministic, so encrypting a value you already know must give
  exactly the `![...]` that is in the file.

## Usage

Open the [online version](https://mysticalhand.github.io/mulesoft-secure-properties/), or download
[`index.html`](index.html) and open it in any browser.

1. Enter the key: the value passed to `key="${...}"` of your `<secure-properties:config>`.
2. If your config sets `algorithm` or `mode`, choose the same ones. Otherwise keep the defaults, AES and CBC.
3. **Encrypt**: type a value and paste the result into the yaml as it is, in quotes: `password: "![...]"`.
4. **Decrypt**: paste `![...]`, bare Base64, or a whole yaml line such as `password: "![...]"`.

## Supported algorithms

| Algorithm | Key length | Block |
|---|---|---|
| AES (default) | exactly 16, 24 or 32 characters | 16 bytes |
| Blowfish | 1 to 56 characters | 8 bytes |
| DES | exactly 8 characters | 8 bytes |
| DESede | exactly 24 characters | 8 bytes |

Modes: CBC (default), CFB, ECB, OFB. Padding: PKCS5.

Mule uses the key string as it is, without any key derivation, so its length has to match the algorithm. With any
other length the runtime itself fails with `The key is invalid, please make sure it's of a supported size`. The tool
checks the same rules as you type.

## How it matches Mule

It does what `org.mule.encryption.jce.JCEEncrypter` does with `ALGORITHM/MODE/PKCS5Padding` and
`useRandomIVs=false`, the default for `<secure-properties:config>`:

- key = bytes of the key string;
- IV = first block-size bytes of the key, zero-padded if the key is shorter (not used in ECB);
- value = `![` + Base64(ciphertext) + `]`.

Not supported: `useRandomIVs="true"`, file-level encryption, and the other algorithms Mule accepts (Camellia,
Twofish, RSA and others).

## Security

- Everything runs in the browser. The page makes no network requests and stores nothing: no cookies, no local
  storage. Its Content-Security-Policy blocks all network access, so nothing you type can leave the page.
- With production keys, prefer your own local copy of `index.html` over a copy hosted somewhere else.
- Anyone who has the key can decrypt every value in the file. Keep it out of the repository and the application
  package, and pass it as a protected deployment property.

## Tests

```
npm test
```

or `node test/test.js`. Needs Node.js 16 or later, no dependencies. The test runs the crypto code taken straight from
`index.html` and checks:

- AES against the FIPS-197 test vectors, DES and Blowfish against published known-answer vectors;
- 220 values produced by the Mule library itself (`mule-secure-configuration-property-module` 1.2.7 with
  `mule-encryption` 1.3.2), covering every algorithm and mode. Each one must encrypt to the identical `![...]` and
  decrypt back to the original value;
- key length rules identical to the library's, for lengths 1 to 60;
- a wrong key or mode never returns the original value.

## Disclaimer

Not affiliated with or endorsed by MuleSoft or Salesforce. MuleSoft is a trademark of Salesforce, Inc.

## License

[MIT](LICENSE)
