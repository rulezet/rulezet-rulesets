rule sig_20160826_531ccc8c85d7f114325dd592a370110d {
  meta:
    description = "datamaliciousorder - file 20160826_531ccc8c85d7f114325dd592a370110d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38590436dd8537673403ddfed4df0d3e219470214eee789ae08e11aa1915dfc4"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}