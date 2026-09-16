rule sig_20161024_1c0e451cff168f97ce43ec17018590ca {
  meta:
    description = "datamaliciousorder - file 20161024_1c0e451cff168f97ce43ec17018590ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0487067da08f3a1f99fff1aa6a13fb36d174f130859a33cab5c0a52a3bf6a50"

  strings:
    $s1 = "} while (jo++ < sd);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}