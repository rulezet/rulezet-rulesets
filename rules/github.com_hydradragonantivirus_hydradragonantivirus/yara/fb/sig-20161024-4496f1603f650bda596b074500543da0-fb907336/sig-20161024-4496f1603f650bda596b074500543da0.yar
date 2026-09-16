rule sig_20161024_4496f1603f650bda596b074500543da0 {
  meta:
    description = "datamaliciousorder - file 20161024_4496f1603f650bda596b074500543da0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d59e3207fc32359b3bfbc5f8424933b13c32a109ded0c4a303e29e246e62195"

  strings:
    $s1 = "} while (vm++ < an);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}