#!/usr/bin/env python3
"""Build a complete signed static tree from reviewed, immutable release pins."""
import argparse
import contextlib
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import gzip
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
UPSTREAM = "ProjectCuriositas/Mognitio"

def run(args, **kwargs):
    env = dict(kwargs.pop("env", os.environ))
    env.pop("APT_SIGNING_KEY", None)
    env.pop("APT_SIGNING_PASSPHRASE", None)
    return subprocess.run(list(map(str, args)), check=True, capture_output=True, env=env, **kwargs).stdout

def sha(data):
    return hashlib.sha256(data).hexdigest()

def fetch(url, limit):
    request = urllib.request.Request(url, headers={"User-Agent": "ProjectCuriositas-APT"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Download exceeds its declared size")
    return data

def config_check(config):
    if config.get("schema") != 1 or config.get("base_url") != "https://projectcuriositas.github.io/apt/":
        raise ValueError("Unexpected repository identity")
    releases = config["releases"]
    if not isinstance(releases, list):
        raise ValueError("Release registry must be a list")
    versions = set()
    for release in releases:
        version = release["version"]
        if not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", version):
            raise ValueError("Only explicit formal upstream versions may be published")
        if version in versions or release["tag"] != "v" + version:
            raise ValueError("Duplicate version or unexpected tag")
        versions.add(version)
        for name, length in (("commit",40),("manifest_sha256",64),("deb_sha256",64)):
            if not re.fullmatch("[0-9a-f]{" + str(length) + "}", release[name]):
                raise ValueError("Missing exact release pin: " + name)
        if not isinstance(release["deb_size"], int) or not 0 < release["deb_size"] <= 100*1024*1024:
            raise ValueError("Invalid package size")
    if releases or any(config.get(field) is not None for field in
                       ("primary_fingerprint","apt_signing_fingerprint","bundle_signing_fingerprint")):
        for field in ("primary_fingerprint","apt_signing_fingerprint","bundle_signing_fingerprint"):
            if not re.fullmatch("[0-9A-F]{40}", config.get(field) or ""):
                raise ValueError("Production key fingerprints are not configured")
        if config["apt_signing_fingerprint"] == config["bundle_signing_fingerprint"]:
            raise ValueError("APT and bundle signing subkeys must be distinct")

def verify_signature(keyring, signature, document, primary, signer):
    status = run(["gpgv","--status-fd","1","--keyring",keyring,signature,document]).decode()
    rows = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if len(rows) != 1 or rows[0][2] != signer or rows[0][-1] != primary:
        raise ValueError("Unexpected signature identity")
    if any(word in status for word in ("REVKEYSIG","EXPKEYSIG","EXPSIG","BADSIG")):
        raise ValueError("Revoked, expired, or invalid signature")

def release_package(release, config, keyring, directory):
    tag = release["tag"]
    api = "https://api.github.com/repos/" + UPSTREAM
    published = json.loads(fetch(api + "/releases/tags/" + tag, 1024*1024))
    if published["draft"] or published["prerelease"] or published["tag_name"] != tag:
        raise ValueError("The pinned release is not a published formal release")
    ref = json.loads(fetch(api + "/git/ref/tags/" + tag, 65536))["object"]
    for _ in range(4):
        if ref["type"] == "commit":
            break
        if ref["type"] != "tag":
            raise ValueError("Invalid release tag object")
        ref = json.loads(fetch(api + "/git/tags/" + ref["sha"],65536))["object"]
    if ref["type"] != "commit" or ref["sha"] != release["commit"]:
        raise ValueError("Release tag no longer matches the reviewed commit")
    base = "https://github.com/" + UPSTREAM + "/releases/download/" + tag + "/"
    manifest_bytes = fetch(base + "manifest.json", 1024*1024)
    if sha(manifest_bytes) != release["manifest_sha256"]:
        raise ValueError("Release manifest differs from reviewed bytes")
    manifest_file = directory / "manifest.json"
    manifest_file.write_bytes(manifest_bytes)
    signature = directory / "manifest.json.asc"
    signature.write_bytes(fetch(base + signature.name, 65536))
    verify_signature(keyring,signature,manifest_file,config["primary_fingerprint"],config["bundle_signing_fingerprint"])
    manifest = json.loads(manifest_bytes)
    identity = manifest["identity"]
    if (identity["version"] != release["version"] or identity["inputs"]["commit"] != release["commit"]
            or identity["inputs"]["dirty"] or identity["inputs"]["mode"] != "release"
            or identity["inputs"]["target"] != "linux-amd64"):
        raise ValueError("Manifest identity disagrees with release registry")
    name = "mognitio_" + release["version"] + "-1_amd64.deb"
    artifacts = [item for item in manifest["artifacts"] if item["filename"] == name]
    if len(artifacts) != 1 or artifacts[0]["sha256"] != release["deb_sha256"] or artifacts[0]["size"] != release["deb_size"]:
        raise ValueError("Package pin disagrees with signed manifest")
    data = fetch(base + name, release["deb_size"])
    if len(data) != release["deb_size"] or sha(data) != release["deb_sha256"]:
        raise ValueError("Package size or digest mismatch")
    package = directory / name
    package.write_bytes(data)
    fields = run(["dpkg-deb","--field",package,"Package","Version","Architecture"]).decode()
    expected = {"Package":"mognitio","Version":release["version"]+"-1","Architecture":"amd64"}
    if dict(line.split(": ",1) for line in fields.splitlines()) != expected:
        raise ValueError("Debian control metadata mismatch")
    return package


def validate_public_keys(directory, keyfile, config):
    home=directory/"public-check";home.mkdir(mode=0o700)
    env=dict(os.environ,GNUPGHOME=str(home))
    run(["gpg","--batch","--import"],input=keyfile.read_bytes(),env=env)
    listing=run(["gpg","--batch","--with-colons","--list-keys"],env=env).decode()
    records={};pending=None;primary=None
    for line in listing.splitlines():
        fields=line.split(":")
        if fields[0] in ("pub","sub"):
            pending=fields
        elif fields[0]=="fpr" and pending:
            if pending[0]=="pub":primary=fields[9]
            records[fields[9]]=(pending,primary);pending=None
    now=int(datetime.now(timezone.utc).timestamp())
    for field,kind in [("primary_fingerprint","pub"),("apt_signing_fingerprint","sub"),("bundle_signing_fingerprint","sub")]:
        row,parent=records[config[field]]
        if row[0]!=kind or parent!=config["primary_fingerprint"] or row[1] in ("r","e","d","i"):
            raise ValueError("Public key is revoked, expired, invalid, or bound to another primary")
        if row[6] and int(row[6])<=now:
            raise ValueError("Public key has expired")
        if kind=="sub" and "s" not in row[11]:
            raise ValueError("Configured subkey cannot sign")

def key_environment(directory, config, secret, public=None):
    home = directory / "gnupg"
    home.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(home))
    # Never forward key material to any subsequent child environment.
    env.pop("APT_SIGNING_KEY",None)
    env.pop("APT_SIGNING_PASSPHRASE",None)
    run(["gpg","--batch","--import"],input=secret.encode(),env=env)
    if public is not None:
        run(["gpg","--batch","--import"],input=public.read_bytes(),env=env)
    listing = run(["gpg","--batch","--with-colons","--list-secret-keys"],env=env).decode()
    primary_rows = [line.split(":") for line in listing.splitlines() if line.startswith("sec:")]
    if len(primary_rows) != 1 or primary_rows[0][14] != "#":
        raise ValueError("CI must contain a stub primary, never the offline primary secret")
    fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
    available=[];pending=None
    for line in listing.splitlines():
        row=line.split(":")
        if row[0] in ("sec","ssb"):pending=row
        elif row[0]=="fpr" and pending:
            if pending[0]=="ssb" and pending[14]!="#":available.append(row[9])
            pending=None
    if fingerprints[0] != config["primary_fingerprint"] or available != [config["apt_signing_fingerprint"]]:
        raise ValueError("Only the designated APT secret subkey may be imported")
    return env

def repository_metadata(site, env, signing, passphrase):
    binary = site / "dists/stable/main/binary-amd64"
    binary.mkdir(parents=True)
    index = run(["dpkg-scanpackages","--multiversion","pool"],cwd=site)
    (binary/"Packages").write_bytes(index)
    (binary/"Packages.gz").write_bytes(gzip.compress(index,mtime=0))
    release = run(["apt-ftparchive",
        "-o","APT::FTPArchive::Release::Origin=ProjectCuriositas",
        "-o","APT::FTPArchive::Release::Label=Mognitio",
        "-o","APT::FTPArchive::Release::Suite=stable",
        "-o","APT::FTPArchive::Release::Codename=stable",
        "-o","APT::FTPArchive::Release::Architectures=amd64",
        "-o","APT::FTPArchive::Release::Components=main",
        "release","dists/stable"],cwd=site)
    release += ("Valid-Until: " + format_datetime(datetime.now(timezone.utc)+timedelta(days=14),usegmt=True)+"\n").encode()
    path = site/"dists/stable/Release";path.write_bytes(release)
    for mode,name in [("--clearsign","InRelease"),("--detach-sign","Release.gpg")]:
        run(["gpg","--batch","--pinentry-mode","loopback","--passphrase-fd","0",
             "--local-user",signing+"!","--output",path.with_name(name),mode,path],
            input=(passphrase+"\n").encode(),env=env)

def landing(site, config):
    if not config["releases"]:
        body = "<h1>ProjectCuriositas APT</h1><p>Repository setup is in progress. No packages are published yet.</p>"
        if config.get("primary_fingerprint"):
            body += '<p><a href="keys/mognitio.asc">Production public key</a></p>'
            for label,field in (("Primary","primary_fingerprint"),("APT signing subkey","apt_signing_fingerprint"),
                                ("Bundle signing subkey","bundle_signing_fingerprint")):
                body += "<p>"+label+" fingerprint: <code>"+config[field]+"</code></p>"
            body += "<p>Compare these fingerprints with the reviewed GitHub repository. GitHub and this Pages site "
            body += "share the same account authority; an independent verification channel is not yet available.</p>"
    else:
        primary=config["primary_fingerprint"]
        body = "<h1>Mognitio APT repository</h1><p>Ubuntu 24.04 / 26.04 amd64; stable/main.</p>"
        body += "<p>Primary fingerprint: <code>"+primary+"</code></p>"
        body += "<p>Verify this fingerprint against the reviewed GitHub repository before installation. "
        body += "An independent verification website is not yet available.</p>"
        commands = (
            "sudo apt update\nsudo apt install --no-install-recommends ca-certificates curl gnupg\n"
            "curl -fsSLo mognitio.asc https://projectcuriositas.github.io/apt/keys/mognitio.asc\n"
            "gpg --show-keys --with-fingerprint mognitio.asc\n"
            "# Compare the complete primary fingerprint above before continuing.\n"
            "sudo install -d -m 0755 /etc/apt/keyrings\n"
            "sudo install -m 0644 mognitio.asc /etc/apt/keyrings/mognitio.asc\n"
            "echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/mognitio.asc] https://projectcuriositas.github.io/apt/ stable main' | sudo tee /etc/apt/sources.list.d/mognitio.list\n"
            "sudo apt update\nsudo apt install mognitio\n")
        body += "<pre>"+html.escape(commands)+"</pre>"
        body += "<p>Metadata expires after 14 days and is renewed weekly. Do not bypass signature or expiry errors.</p>"
    body += '<p><a href="https://github.com/ProjectCuriositas/apt">Source and operations</a></p>'
    (site/"index.html").write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>ProjectCuriositas APT</title><body>'+body+'</body></html>\n')
    (site/".nojekyll").touch()

def build(config, keyfile, output):
    config_check(config)
    if output.exists():
        raise ValueError("Use a new output directory")
    with tempfile.TemporaryDirectory(prefix="apt-build-") as temporary, contextlib.ExitStack() as cleanup:
        directory=Path(temporary);site=directory/"site";site.mkdir()
        if config.get("primary_fingerprint"):
            if not keyfile.is_file() or keyfile.is_symlink():
                raise ValueError("Missing production public key")
            cleanup.callback(subprocess.run,["gpgconf","--homedir",str(directory/"public-check"),"--kill","gpg-agent"],capture_output=True)
            validate_public_keys(directory,keyfile,config)
            keys=site/"keys";keys.mkdir();shutil.copyfile(keyfile,keys/"mognitio.asc")
        if config["releases"]:
            keyring=directory/"public.gpg"
            keyring.write_bytes(run(["gpg","--batch","--dearmor"],input=keyfile.read_bytes()))
            pool=site/"pool/main/m/mognitio";pool.mkdir(parents=True)
            for i,release in enumerate(config["releases"]):
                downloaded=directory/str(i);downloaded.mkdir()
                package=release_package(release,config,keyring,downloaded)
                shutil.copy2(package,pool/package.name)
            secret=os.environ.get("APT_SIGNING_KEY","")
            if not secret:
                raise ValueError("APT signing subkey secret is missing")
            # Register cleanup before import so failure also closes the agent.
            cleanup.callback(subprocess.run,["gpgconf","--homedir",str(directory/"gnupg"),"--kill","gpg-agent"],capture_output=True)
            env=key_environment(directory,config,secret,keyfile)
            repository_metadata(site,env,config["apt_signing_fingerprint"],os.environ.get("APT_SIGNING_PASSPHRASE",""))
            verify_signature(keyring,site/"dists/stable/Release.gpg",site/"dists/stable/Release",
                             config["primary_fingerprint"],config["apt_signing_fingerprint"])
            extracted=run(["gpgv","--keyring",keyring,"--output","-",site/"dists/stable/InRelease"])
            if extracted != (site/"dists/stable/Release").read_bytes():
                raise ValueError("Clear-signed metadata differs from Release")
        landing(site,config)
        # Copy only the public tree after every verification succeeds.
        shutil.copytree(site,output)

def verify_signing_config(config, keyfile):
    """Exercise real APT signatures privately without publishing a repository."""
    config_check(config)
    if not config.get("primary_fingerprint") or not keyfile.is_file() or keyfile.is_symlink():
        raise ValueError("Production public key must be configured first")
    secret=os.environ.get("APT_SIGNING_KEY","")
    passphrase=os.environ.get("APT_SIGNING_PASSPHRASE","")
    if not secret or not passphrase:
        raise ValueError("Signing key and passphrase secrets must both be configured")
    with tempfile.TemporaryDirectory(prefix="apt-signing-check-") as temporary, contextlib.ExitStack() as cleanup:
        directory=Path(temporary)
        for home in ("public-check","gnupg"):
            cleanup.callback(subprocess.run,["gpgconf","--homedir",str(directory/home),"--kill","gpg-agent"],capture_output=True)
        validate_public_keys(directory,keyfile,config)
        env=key_environment(directory,config,secret,keyfile)
        site=directory/"private-probe";site.mkdir();(site/"pool").mkdir()
        repository_metadata(site,env,config["apt_signing_fingerprint"],passphrase)
        keyring=directory/"public.gpg"
        keyring.write_bytes(run(["gpg","--batch","--dearmor"],input=keyfile.read_bytes()))
        release=site/"dists/stable/Release"
        verify_signature(keyring,release.with_name("Release.gpg"),release,
                         config["primary_fingerprint"],config["apt_signing_fingerprint"])
        clear=run(["gpgv","--keyring",keyring,"--output","-",release.with_name("InRelease")])
        if clear!=release.read_bytes():
            raise ValueError("Signing probe contents differ")
    print("APT signing configuration verified; no package or repository was published.")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output",type=Path)
    mode.add_argument("--check-signing",action="store_true")
    args=parser.parse_args()
    config=json.loads((ROOT/"repository.json").read_text())
    if args.check_signing:
        verify_signing_config(config,ROOT/"keys/mognitio.asc")
    else:
        build(config,ROOT/"keys/mognitio.asc",args.output.resolve())
