rule sig_20161024_6cd4023f9e562be2838474b92dc9c49e {
  meta:
    description = "datamaliciousorder - file 20161024_6cd4023f9e562be2838474b92dc9c49e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb60311ef40cc58878786184db4d2239ceb8bbde7a2dc0270533aa8f349b471c"

  strings:
    $s1 = "} while (mb++ < vy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}