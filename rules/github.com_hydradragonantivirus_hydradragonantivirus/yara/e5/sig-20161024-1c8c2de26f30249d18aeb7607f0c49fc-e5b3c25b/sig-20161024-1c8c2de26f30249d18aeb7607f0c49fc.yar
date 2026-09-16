rule sig_20161024_1c8c2de26f30249d18aeb7607f0c49fc {
  meta:
    description = "datamaliciousorder - file 20161024_1c8c2de26f30249d18aeb7607f0c49fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a50899daeb571789662f3cf7a09f2c16d7e63830c84d3990b12cded59d6f8d8"

  strings:
    $s1 = "} while (ln++ < ux);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}