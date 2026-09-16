rule sig_20161024_9957b2c457295f6cb65fde6f6d0e2d89 {
  meta:
    description = "datamaliciousorder - file 20161024_9957b2c457295f6cb65fde6f6d0e2d89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cc578ed84fd9d35090550e601c606d0206866a3179a04c426d0f5d53dff5663"

  strings:
    $s1 = "} while (pz++ < wz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}