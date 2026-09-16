rule sig_20161024_32f6de9b0791e4e2cfe1a86ea2e571f4 {
  meta:
    description = "datamaliciousorder - file 20161024_32f6de9b0791e4e2cfe1a86ea2e571f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "822d6ec039c7b5c0c4feb7f7b56f3515adc6fdd568b53df3788cd6c533796b5c"

  strings:
    $s1 = "} while (xr++ < kn1);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}