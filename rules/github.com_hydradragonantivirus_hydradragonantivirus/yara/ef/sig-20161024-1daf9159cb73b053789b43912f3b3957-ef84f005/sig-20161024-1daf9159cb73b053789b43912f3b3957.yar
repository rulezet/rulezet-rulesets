rule sig_20161024_1daf9159cb73b053789b43912f3b3957 {
  meta:
    description = "datamaliciousorder - file 20161024_1daf9159cb73b053789b43912f3b3957.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c8a55d5b7df809db720e5dde749f57789d205389d18c64af370f9729b10b73b"

  strings:
    $s1 = "} while (hd++ < zl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}