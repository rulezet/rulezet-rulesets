rule sig_20161024_49ef0e0c7d9784e6f16f489b3f71804d {
  meta:
    description = "datamaliciousorder - file 20161024_49ef0e0c7d9784e6f16f489b3f71804d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1769745de15a07806772c78a09231c66bc4d4a9b2dfcaa9b3c1ce3e3d3efb182"

  strings:
    $s1 = "} while (oe++ < uf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}