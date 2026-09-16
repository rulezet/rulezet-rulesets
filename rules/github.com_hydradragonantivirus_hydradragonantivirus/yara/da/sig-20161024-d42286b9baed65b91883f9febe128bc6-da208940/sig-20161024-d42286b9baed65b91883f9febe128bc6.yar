rule sig_20161024_d42286b9baed65b91883f9febe128bc6 {
  meta:
    description = "datamaliciousorder - file 20161024_d42286b9baed65b91883f9febe128bc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "413885fea1feac73689633d4020d6f20a66ce0432a5fa13c82de0afde876d73e"

  strings:
    $s1 = "} while (rq++ < dm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}