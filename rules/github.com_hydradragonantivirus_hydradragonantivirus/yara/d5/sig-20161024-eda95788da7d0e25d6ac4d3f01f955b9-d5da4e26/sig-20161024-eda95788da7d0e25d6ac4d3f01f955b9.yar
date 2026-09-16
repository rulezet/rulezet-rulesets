rule sig_20161024_eda95788da7d0e25d6ac4d3f01f955b9 {
  meta:
    description = "datamaliciousorder - file 20161024_eda95788da7d0e25d6ac4d3f01f955b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ccd6aef1c85d35826a6ed6989d5af0b1315e4facb487210e88bd4c1197d9ab4"

  strings:
    $s1 = "} while (mr++ < ht0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}