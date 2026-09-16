rule sig_20161024_3d4504031e7be09a58e49eb0992902bd {
  meta:
    description = "datamaliciousorder - file 20161024_3d4504031e7be09a58e49eb0992902bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "195ceba96ecb3fcf48ec45bc58519cce2fab8b4ed4ea1dcc14e08e0a1d4b29f0"

  strings:
    $s1 = "} while (sy++ < nx);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}