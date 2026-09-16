rule Virus_Hijack_Trojan_GenericKDZ_103285_655 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_655.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38b6a57fb26c7005438d8647b028a39c34ea7040a43cd85429c16bafba2b617d"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}