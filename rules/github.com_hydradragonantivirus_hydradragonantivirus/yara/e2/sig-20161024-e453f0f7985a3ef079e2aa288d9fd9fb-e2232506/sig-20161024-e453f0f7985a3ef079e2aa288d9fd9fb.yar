rule sig_20161024_e453f0f7985a3ef079e2aa288d9fd9fb {
  meta:
    description = "datamaliciousorder - file 20161024_e453f0f7985a3ef079e2aa288d9fd9fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ea28dbbf4a399666fc8cd53c053a0d12588a55e221cda07432e8f9e95ba79ee"

  strings:
    $s1 = "} while (sk++ < kk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}