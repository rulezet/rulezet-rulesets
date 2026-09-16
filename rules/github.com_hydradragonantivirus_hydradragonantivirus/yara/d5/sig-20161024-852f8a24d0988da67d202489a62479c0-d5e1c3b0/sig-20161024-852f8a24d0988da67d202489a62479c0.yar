rule sig_20161024_852f8a24d0988da67d202489a62479c0 {
  meta:
    description = "datamaliciousorder - file 20161024_852f8a24d0988da67d202489a62479c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24e5d7cc2e58a6400d407b51867886cd05247334301c9366407dddf99cf76c80"

  strings:
    $s1 = "} while (zl++ < oc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}