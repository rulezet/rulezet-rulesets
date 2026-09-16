rule sig_20161024_464be3b5de28e2a76b90d51b3c23605c {
  meta:
    description = "datamaliciousorder - file 20161024_464be3b5de28e2a76b90d51b3c23605c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1cfe3940a7c03a023fb4a12c9b91a1cb75edf888612f72219784157ea7ab32c"

  strings:
    $s1 = "} while (qo++ < cl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}