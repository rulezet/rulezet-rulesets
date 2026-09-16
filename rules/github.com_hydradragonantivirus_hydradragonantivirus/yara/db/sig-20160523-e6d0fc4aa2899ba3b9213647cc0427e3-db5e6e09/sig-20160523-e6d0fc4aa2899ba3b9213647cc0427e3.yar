rule sig_20160523_e6d0fc4aa2899ba3b9213647cc0427e3 {
  meta:
    description = "datamaliciousorder - file 20160523_e6d0fc4aa2899ba3b9213647cc0427e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "455beb2ade436da12396e1059822b8252fe9582d5aff2f59063c8b89115db4ad"

  strings:
    $s1 = "join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}