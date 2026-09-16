rule sig_20160823_fa1efffc0f04525281f711052d29d15c {
  meta:
    description = "datamaliciousorder - file 20160823_fa1efffc0f04525281f711052d29d15c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4a1864869c963878cdcbd148807c3dd0e8ad42694a3a1c8f4739db390551e8"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}