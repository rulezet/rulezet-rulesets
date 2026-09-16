rule sig_20160517_7a38bdd0777525151d272af8048948c7 {
  meta:
    description = "datamaliciousorder - file 20160517_7a38bdd0777525151d272af8048948c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fd2d4937885274cd782d9a71bf8010df38b4672481f127d5592514aed87350e"

  strings:
    $s1 = "var y2g3='vcxgnmapzoivraz1rt egxyqjoy2fzhrbbggtund1brz4aimgizl1rcs12dz2xixtrvggw3q1msekt=ldxop\\'jopzotqfpimcr4ymxnzjenlibueeefe" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}