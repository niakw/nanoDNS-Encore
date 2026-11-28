"""Documentation contracts for the hardened DNS runtime."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
BANNED=re.compile(r"\b(?:sony|nintendo|playstation|xbox|microsoft|epic|rockstar|ubisoft|sega|cloudflare|google|capcom|bandai|namco|steam|valve|gog|psn|ps4|ps5|ps3|akamai|electronic arts|take.two|square enix|cd projekt|dualsense|sie|wii|switch)\b",re.I)
PAIRS=(
 ("README.md","README.fr.md"),
 ("ACCESSIBILITY.md","ACCESSIBILITY.fr.md"),
 ("CONTRIBUTING.md","CONTRIBUTING.fr.md"),
 ("CODE_OF_CONDUCT.md","CODE_OF_CONDUCT.fr.md"),
 ("SECURITY.md","SECURITY.fr.md"),
 ("CHANGELOG.md","CHANGELOG.fr.md"),
 ("docs/CREDITS.md","docs/CREDITS.fr.md"),
 ("docs/DNS_POLICY.md","docs/DNS_POLICY.fr.md"),
 ("docs/INSTALL.md","docs/INSTALL.fr.md"),
 ("docs/PS5_13_60_LIFECYCLE.md","docs/PS5_13_60_LIFECYCLE.fr.md"),
 ("docs/TEST_PLAN.md","docs/TEST_PLAN.fr.md"),
)

class DocumentationContracts(unittest.TestCase):
 def test_language_pairs(self):
  for en,fr in PAIRS:
   with self.subTest(en=en):
    a=ROOT/en;b=ROOT/fr
    self.assertTrue(a.is_file());self.assertTrue(b.is_file())
    self.assertIn(b.name,a.read_text(encoding="utf-8"))
    self.assertIn(a.name,b.read_text(encoding="utf-8"))

 def test_english_install_is_default(self):
  en=(ROOT/"README.md").read_text(encoding="utf-8")
  self.assertIn("(docs/INSTALL.md)",en)
  self.assertIn("(docs/INSTALL.fr.md)",en)
  self.assertLess(en.index("(docs/INSTALL.md)"),en.index("(docs/INSTALL.fr.md)"))
  for name in ("README.md","README.fr.md"):
   s=(ROOT/name).read_text(encoding="utf-8")
   for term in ("124","Control D","Drakmor"):
    self.assertIn(term,s)
  self.assertIn("hardware",en.lower())
  self.assertIn("not",en.lower())

 def test_upgrade_from_original_is_explicit(self):
  en=(ROOT/"docs/INSTALL.md").read_text(encoding="utf-8")
  fr=(ROOT/"docs/INSTALL.fr.md").read_text(encoding="utf-8")
  for s in (en,fr):
   for token in ("Payload Manager","nanodns.elf","/data/nanodns/nanodns.ini","127.0.0.1","76.76.2.0","76.76.10.0","94.140.14.140","94.140.14.141"):
    self.assertIn(token,s)
  for token in ("Drakmor","original","autoload","Rollback"):
   self.assertIn(token,en)
  for token in ("Drakmor","officiel","autoload","Retour arrière"):
   self.assertIn(token,fr)
  self.assertIn("Upgrade from Drakmor",en)
  self.assertIn("Migration depuis le nanoDNS",fr)

 def test_zip_upgrade_instructions_contract(self):
  en=(ROOT/"docs/INSTALL.md").read_text(encoding="utf-8")
  fr=(ROOT/"docs/INSTALL.fr.md").read_text(encoding="utf-8")
  r=(ROOT/"release/RELEASE_NOTES.md").read_text(encoding="utf-8")
  paths=("/data/pldmgr/payloads/local/nanodns/nanodns.elf","/data/nanodns/nanodns4096.ini")
  for s in (en,fr,r):
   for path in paths:
    self.assertIn(path,s)
   self.assertIn("local/nanodns",s)
   self.assertIn("nanodns-13.60-v0.4-13.60.4-install.zip",s)
  for s in (en,fr):
   self.assertIn("nanodns@e8cce5d1",s)
   self.assertIn("Payload Manager",s)
   self.assertIn("autoload",s)
   self.assertIn("/data/data/",s)
  for s in ((ROOT/"README.md").read_text(encoding="utf-8"),(ROOT/"README.fr.md").read_text(encoding="utf-8")):
   self.assertIn("nanodns-13.60-v0.4-13.60.4-install.zip",s)
   self.assertIn("local/nanodns",s)

 def test_hardware_user_test_status_is_scoped(self):
  en=(ROOT/"README.md").read_text(encoding="utf-8")
  fr=(ROOT/"README.fr.md").read_text(encoding="utf-8")
  note=(ROOT/"release/RELEASE_NOTES.md").read_text(encoding="utf-8")
  p_en=(ROOT/"docs/TEST_PLAN.md").read_text(encoding="utf-8")
  p_fr=(ROOT/"docs/TEST_PLAN.fr.md").read_text(encoding="utf-8")
  self.assertIn("USER-TESTED",en)
  self.assertIn("NOT USER-VALIDATED",en)
  self.assertIn("0.4-13.60.4",fr)
  self.assertIn("1719",fr)
  self.assertIn("15/15",en)
  self.assertIn("15/15",note)
  self.assertIn("15/15",p_en)
  self.assertIn("15/15",p_fr)
  self.assertIn("7/7",note)
  for doc in (en,fr,note,p_en,p_fr):
   self.assertIn("0.4-13.60.4",doc)
   self.assertIn("1719",doc)
  self.assertIn("normal shutdown and subsequent power-on",note)
  self.assertIn("extinction normale",note)
  self.assertIn("shutdown/power-on",p_en)
  self.assertIn("extinction normale",p_fr)

  self.assertIn("NON VALIDÉ",fr)
  self.assertIn("23 blocked A queries",note)
  self.assertIn("NOT USER-VALIDATED",note)
  self.assertIn("23 observed A queries",p_en)
  self.assertIn("23 requêtes A",p_fr)
  for text in (en,fr,note,p_en,p_fr):
   self.assertIn("13.60",text)
   self.assertIn("Control D",text)
   self.assertIn("shutdown",text.lower())

 def test_standard_release_documentation(self):
  notes=(ROOT/"release/RELEASE_NOTES.md").read_text(encoding="utf-8")
  en=(ROOT/"README.md").read_text(encoding="utf-8")
  fr=(ROOT/"README.fr.md").read_text(encoding="utf-8")
  wf=(ROOT/".github/workflows/package-install-zip.yml").read_text(encoding="utf-8")
  for key in ("Standard GitHub Release","NOT USER-VALIDATED","13.60"):
   self.assertIn(key,notes)
  self.assertIn("standard GitHub Release",en)
  self.assertIn("Release GitHub standard",fr)
  self.assertNotIn("gh release edit",wf)
  self.assertIn("workflow_dispatch",wf)
  publisher=(ROOT/".github/workflows/publish-rc.yml").read_text(encoding="utf-8")
  self.assertIn("dist/nanodns.elf",publisher)
  self.assertIn("dist/nanodns-ps4.elf",publisher)
  self.assertIn("nanodns-13.60-v0.4-13.60.4-install.zip",publisher)
  self.assertIn("--latest",publisher)
  self.assertIn("v0.4-13.60.4",notes)
  self.assertIn("0.4-13.60.4",en)
  self.assertIn("0.4-13.60.4",fr)
  self.assertIn("0.4-13.60.4 DNS PATH: USER-TESTED",notes)
  self.assertIn("0.4-13.60.1",notes)

 def test_project_community_documents_are_complete(self):
  files=("ACCESSIBILITY.md","ACCESSIBILITY.fr.md","CONTRIBUTING.md",
         "CONTRIBUTING.fr.md","CODE_OF_CONDUCT.md","CODE_OF_CONDUCT.fr.md",
         ".github/ISSUE_TEMPLATE/bug_report.md",
         ".github/ISSUE_TEMPLATE/feature_request.md",
         ".github/ISSUE_TEMPLATE/custom.md")
  for path in files:
   s=(ROOT/path).read_text(encoding="utf-8")
   with self.subTest(path=path):
    self.assertGreater(len(s.strip()),300)
    self.assertNotIn("<!--",s)
    self.assertNotIn("mailto:",s)
    self.assertIn("nanoDNS",s)
  dep=(ROOT/".github/dependabot.yml").read_text(encoding="utf-8")
  self.assertIn('package-ecosystem: "github-actions"',dep)
  self.assertNotIn('package-ecosystem: ""',dep)
  for path in (".github/workflows/ps4.yml",".github/workflows/ps5.yml"):
   s=(ROOT/path).read_text(encoding="utf-8")
   self.assertIn("permissions:\n  contents: read",s)
   self.assertNotIn("prerelease: true",s)
   self.assertNotIn("\n  release:",s)

 def test_no_visible_commercial_platform_names(self):
  for file in ROOT.rglob("*.md"):
   s=file.read_text(encoding="utf-8")
   s=re.sub(r"\]\([^)]*\)","]()",s)
   s=re.sub(r"https?://[^\s)>]+","",s)
   # Exempt exact technical artifact filenames, but not marketing prose.
   s=re.sub(r"`[^`\n]*`","",s)
   m=BANNED.search(s)
   self.assertIsNone(m, f"{file.relative_to(ROOT)}: {m.group(0) if m else ''}")

 def test_all_local_markdown_links(self):
  for file in ROOT.rglob("*.md"):
   s=file.read_text(encoding="utf-8")
   for href in re.findall(r"\]\(([^)]+)\)",s):
    if href.startswith(("https:","http:","#","mailto:")):continue
    path=href.split("#",1)[0].split("?",1)[0]
    if not path:continue
    with self.subTest(file=str(file.relative_to(ROOT)),link=href):
     self.assertTrue((file.parent/path).is_file())

if __name__=="__main__":
 unittest.main()
