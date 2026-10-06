"""Exercise signature boundaries using disposable, passphrase-protected keys."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location("apt_build",ROOT/"scripts/build.py")
build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
PASSWORD="disposable-test-key-passphrase"

class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="apt-tests-")
        cls.root=Path(cls.temp.name);cls.home=cls.root/"keys";cls.home.mkdir(mode=0o700)
        cls.env=dict(os.environ,GNUPGHOME=str(cls.home))
        def gpg(*args):
            return build.run(["gpg","--batch","--pinentry-mode","loopback","--passphrase-fd","0",*args],
                             input=(PASSWORD+"\n").encode(),env=cls.env)
        cls.gpg=staticmethod(gpg)
        gpg("--quick-gen-key","Disposable APT fixture","ed25519","cert","1d")
        def fingerprints():
            return [line.split(":")[9] for line in gpg("--with-colons","--list-keys").decode().splitlines() if line.startswith("fpr:")]
        cls.primary=fingerprints()[0]
        gpg("--quick-add-key",cls.primary,"ed25519","sign","1d");cls.apt=fingerprints()[1]
        gpg("--quick-add-key",cls.primary,"ed25519","sign","1d");cls.bundle=fingerprints()[2]
        cls.key=cls.root/"public.asc";cls.key.write_bytes(gpg("--armor","--export",cls.primary))
        cls.secret=gpg("--armor","--export-secret-subkeys",cls.apt+"!").decode()
        staging=cls.root/"deb";(staging/"DEBIAN").mkdir(parents=True)
        (staging/"DEBIAN/control").write_text("Package: mognitio\nVersion: 0.15.0-1\nArchitecture: amd64\nMaintainer: ProjectCuriositas\nDescription: Disposable acceptance fixture\n")
        cls.deb=cls.root/"mognitio_0.15.0-1_amd64.deb"
        build.run(["dpkg-deb","--root-owner-group","--build",staging,cls.deb])
        cls.commit="a"*40
        identity={"version":"0.15.0","inputs":{"commit":cls.commit,"dirty":False,"mode":"release","target":"linux-amd64"}}
        cls.manifest=cls.root/"manifest.json"
        cls.manifest.write_text(json.dumps({"identity":identity,"artifacts":[{"filename":cls.deb.name,"size":cls.deb.stat().st_size,"sha256":build.sha(cls.deb.read_bytes())}]}))
        gpg("--armor","--local-user",cls.bundle+"!","--output",str(cls.root/"manifest.json.asc"),"--detach-sign",str(cls.manifest))
        cls.config={"schema":1,"base_url":"https://projectcuriositas.github.io/apt/",
            "primary_fingerprint":cls.primary,"apt_signing_fingerprint":cls.apt,"bundle_signing_fingerprint":cls.bundle,
            "releases":[{"version":"0.15.0","tag":"v0.15.0","commit":cls.commit,"manifest_sha256":build.sha(cls.manifest.read_bytes()),
                         "deb_sha256":build.sha(cls.deb.read_bytes()),"deb_size":cls.deb.stat().st_size}]}

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["gpgconf","--homedir",str(cls.home),"--kill","gpg-agent"],capture_output=True)
        cls.temp.cleanup()

    def fetch(self,url,limit):
        if "/releases/tags/" in url:
            return json.dumps({"draft":False,"prerelease":False,"tag_name":"v0.15.0"}).encode()
        if "/git/ref/tags/" in url:
            return json.dumps({"object":{"type":"commit","sha":self.commit}}).encode()
        return (self.root/url.rsplit("/",1)[-1]).read_bytes()

    def test_bootstrap_has_no_install_commands_or_unsigned_metadata(self):
        config=json.loads((ROOT/"repository.json").read_text())
        config["releases"]=[]
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp)/"site";build.build(config,Path(temp)/"absent",out)
            self.assertNotIn("apt install", (out/"index.html").read_text())
            self.assertFalse((out/"dists").exists())

    def test_registry_rejects_prereleases_duplicates_and_missing_pins(self):
        for change in [lambda c:c["releases"][0].update(version="0.15.0-rc.1"),
                       lambda c:c["releases"].append(c["releases"][0]),
                       lambda c:c["releases"][0].update(commit="main"),
                       lambda c:c.update(primary_fingerprint=None)]:
            config=copy.deepcopy(self.config);change(config)
            with self.assertRaises(ValueError):build.config_check(config)

    def test_complete_tree_contains_verified_bytes_only(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(build,"fetch",self.fetch),patch.dict(os.environ,APT_SIGNING_KEY=self.secret,APT_SIGNING_PASSPHRASE=PASSWORD):
            out=Path(temp)/"site";build.build(self.config,self.key,out)
            self.assertEqual((out/"pool/main/m/mognitio"/self.deb.name).read_bytes(),self.deb.read_bytes())
            self.assertIn("Valid-Until:",(out/"dists/stable/Release").read_text())
            self.assertIn("sudo apt install mognitio",(out/"index.html").read_text())
            for p in out.rglob("*"):
                if p.is_file():
                    self.assertNotIn(b"PRIVATE KEY",p.read_bytes())
                    self.assertNotIn(PASSWORD.encode(),p.read_bytes())
            self.assertFalse(any(p.is_symlink() for p in out.rglob("*")))

    def test_tampered_release_leaves_no_output_tree(self):
        for suffix in [self.deb.name,"manifest.json","manifest.json.asc"]:
            def altered(url,limit):
                data=self.fetch(url,limit)
                return data+b"x" if url.endswith("/"+suffix) else data
            with self.subTest(suffix=suffix),tempfile.TemporaryDirectory() as temp,patch.object(build,"fetch",altered):
                out=Path(temp)/"site"
                with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                    build.build(self.config,self.key,out)
                self.assertFalse(out.exists())

    def test_missing_secret_does_not_publish_unsigned_tree(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(build,"fetch",self.fetch),patch.dict(os.environ,APT_SIGNING_KEY=""):
            out=Path(temp)/"site"
            with self.assertRaisesRegex(ValueError,"secret is missing"):build.build(self.config,self.key,out)
            self.assertFalse(out.exists())

    def test_full_primary_secret_and_wrong_subkey_are_rejected(self):
        full=self.gpg("--armor","--export-secret-keys",self.primary).decode()
        wrong=self.gpg("--armor","--export-secret-subkeys",self.bundle+"!").decode()
        for secret in (full,wrong):
            with tempfile.TemporaryDirectory() as temp:
                directory=Path(temp)
                try:
                    with self.assertRaises(ValueError):build.key_environment(directory,self.config,secret)
                finally:subprocess.run(["gpgconf","--homedir",str(directory/"gnupg"),"--kill","gpg-agent"],capture_output=True)

    def test_nonformal_release_or_moved_tag_is_rejected(self):
        for bad in ("prerelease","tag"):
            def altered(url,limit):
                value=json.loads(self.fetch(url,limit))
                if bad=="prerelease" and "/releases/tags/" in url:value["prerelease"]=True
                if bad=="tag" and "/git/ref/" in url:value["object"]["sha"]="b"*40
                return json.dumps(value).encode()
            with tempfile.TemporaryDirectory() as temp,patch.object(build,"fetch",altered):
                with self.assertRaises(ValueError):
                    build.release_package(self.config["releases"][0],self.config,self.key,Path(temp))

    def test_revoked_public_key_blocks_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);home=root/"revocation";home.mkdir(mode=0o700)
            env=dict(os.environ,GNUPGHOME=str(home))
            try:
                build.run(["gpg","--batch","--import"],input=self.key.read_bytes(),env=env)
                certificate=(self.home/"openpgp-revocs.d"/(self.primary+".rev")).read_text()
                certificate=certificate[certificate.index(":-----BEGIN"):].replace(":-----BEGIN","-----BEGIN",1)
                build.run(["gpg","--batch","--import"],input=certificate.encode(),env=env)
                revoked=root/"revoked.asc"
                revoked.write_bytes(build.run(["gpg","--batch","--armor","--export",self.primary],env=env))
                with self.assertRaisesRegex(ValueError,"revoked"):
                    build.build(self.config,revoked,root/"site")
                self.assertFalse((root/"site").exists())
            finally:subprocess.run(["gpgconf","--homedir",str(home),"--kill","gpg-agent"],capture_output=True)

    def test_real_apt_accepts_generated_index_and_package(self):
        import pwd
        with tempfile.TemporaryDirectory() as temp,patch.object(build,"fetch",self.fetch),patch.dict(os.environ,APT_SIGNING_KEY=self.secret,APT_SIGNING_PASSPHRASE=PASSWORD):
            root=Path(temp);site=root/"site";build.build(self.config,self.key,site)
            (root/"lists/partial").mkdir(parents=True);(root/"downloads").mkdir()
            sources=root/"sources.list"
            sources.write_text("deb [signed-by="+str(site/"keys/mognitio.asc")+"] file:"+str(site)+" stable main\n")
            options=["-o","Dir::Etc::main=-","-o","Dir::Etc::parts=-",
                "-o","Dir::Etc::sourcelist="+str(sources),"-o","Dir::Etc::sourceparts=-",
                "-o","Dir::State::lists="+str(root/"lists"),"-o","APT::Update::Error-Mode=any",
                "-o","APT::Sandbox::User="+pwd.getpwuid(os.getuid()).pw_name]
            build.run(["apt-get",*options,"update"])
            build.run(["apt-get",*options,"download","mognitio"],cwd=root/"downloads")
            self.assertEqual((root/"downloads"/self.deb.name).read_bytes(),self.deb.read_bytes())
