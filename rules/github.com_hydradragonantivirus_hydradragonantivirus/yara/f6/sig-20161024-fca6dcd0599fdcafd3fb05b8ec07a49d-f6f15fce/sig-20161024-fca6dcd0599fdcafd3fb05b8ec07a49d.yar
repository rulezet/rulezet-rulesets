rule sig_20161024_fca6dcd0599fdcafd3fb05b8ec07a49d {
  meta:
    description = "datamaliciousorder - file 20161024_fca6dcd0599fdcafd3fb05b8ec07a49d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a913152cad69193906938043fe860242a9b76b31ed718827f648b6ddfb216b53"

  strings:
    $s1 = "} while (gk++ < bv0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}