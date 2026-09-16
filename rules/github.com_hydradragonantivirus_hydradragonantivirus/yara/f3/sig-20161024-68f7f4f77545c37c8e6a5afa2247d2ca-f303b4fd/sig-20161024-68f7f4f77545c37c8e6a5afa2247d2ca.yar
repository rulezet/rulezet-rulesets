rule sig_20161024_68f7f4f77545c37c8e6a5afa2247d2ca {
  meta:
    description = "datamaliciousorder - file 20161024_68f7f4f77545c37c8e6a5afa2247d2ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78364327f17b51f291c2f9d2662b52be590ea64eccbc2b3faa548e387b211623"

  strings:
    $s1 = "} while (sh++ < op);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}