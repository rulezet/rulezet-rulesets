rule sig_20161024_aada1a159a52a6127fb3c945f42f2946 {
  meta:
    description = "datamaliciousorder - file 20161024_aada1a159a52a6127fb3c945f42f2946.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f6efb0fc5b8136c350cf9f5fe03e16f5302338bb39ab03bf4b5a7a3f7185af8"

  strings:
    $s1 = "} while (ui++ < jp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}