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
