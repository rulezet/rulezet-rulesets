rule sig_20160523_8b3137b6e091223cade165888d51d5ca {
  meta:
    description = "datamaliciousorder - file 20160523_8b3137b6e091223cade165888d51d5ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4069db35b1026af4da0f560fa51b56a175434e1b7a2b7c2d1477c8f1c18857d"

  strings:
    $s1 = "reverse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}