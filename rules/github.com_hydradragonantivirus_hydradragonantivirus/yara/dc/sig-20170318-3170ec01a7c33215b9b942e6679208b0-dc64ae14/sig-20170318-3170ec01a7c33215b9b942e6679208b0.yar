rule sig_20170318_3170ec01a7c33215b9b942e6679208b0 {
  meta:
    description = "datamaliciousorder - file 20170318_3170ec01a7c33215b9b942e6679208b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e2ce14ae29e8aec4d9e2eaed28c00c384c847e492fb248f9e26ebf9e935683f"

  strings:
    $s1 = "split(\" \");" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}