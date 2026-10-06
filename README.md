# ProjectCuriositas APT repository

Signed Linux distribution hosted at [GitHub Pages](https://projectcuriositas.github.io/apt/).

Repository registration is being prepared. No package is published until the
production public key and an approved release are configured in repository.json.
The site only displays install commands after signed metadata has been verified.

Supported initial target: Mognitio on Ubuntu 24.04 and 26.04 amd64, stable/main.

- [Operations](OPERATIONS.md): publication, verification, renewal and recovery.
- [Key ceremony](KEYS.md): offline primary key and separate signing subkeys.
- [Contributing](CONTRIBUTING.md): changes, local validation and pull requests.

All package bytes come from explicit published releases in
[ProjectCuriositas/Mognitio](https://github.com/ProjectCuriositas/Mognitio/releases).
A change to the release registry is reviewed separately from metadata renewal.

## Production public key

The [public key](keys/mognitio.asc) has the following full fingerprints:

| Purpose | Fingerprint |
| --- | --- |
| Offline certification primary | `C44A5AA9313FFA686779C262333C4A7C92BCBDA3` |
| APT metadata signing subkey | `686C282ED80F64536B215571FC0DDC08D041EC45` |
| Bundle manifest signing subkey | `4245611FC8A78B4B900CDF4F6CA5FC1ED455DC71` |

GitHub and this Pages site share the same account authority. An independent
verification channel is not yet available; see [initial trust](OPERATIONS.md#initial-trust-and-revocation).
Publishing this key does not indicate that packages or signing secrets are ready.
