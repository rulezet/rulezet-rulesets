rule sig_20161024_1c72fccedb125f647b2707a0cf8fbca4 {
  meta:
    description = "datamaliciousorder - file 20161024_1c72fccedb125f647b2707a0cf8fbca4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eff67a73c37f7ec92751d236a3faf944ef5b9a2eff9c2684b5bcccc790d7e9f2"

  strings:
    $s1 = "} while (tg++ < fh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}