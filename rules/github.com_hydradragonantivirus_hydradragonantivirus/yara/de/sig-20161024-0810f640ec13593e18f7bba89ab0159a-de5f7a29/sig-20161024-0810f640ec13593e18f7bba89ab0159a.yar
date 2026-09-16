rule sig_20161024_0810f640ec13593e18f7bba89ab0159a {
  meta:
    description = "datamaliciousorder - file 20161024_0810f640ec13593e18f7bba89ab0159a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1deddd2a502c3750b8319d364a068af82190b617b8e89ce6be59e7c513aeffc8"

  strings:
    $s1 = "} while (zw++ < ni);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}