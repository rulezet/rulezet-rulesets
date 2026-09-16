rule Virus_Hijack_Trojan_GenericKDZ_103285_328 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_328.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94388e127465829b06df8446c25a98fd759fe005fd2aecb9d24a34e1c8060602"

  strings:
    $s1 = "tWUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}