rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d87640f08b25a3c0b70d4131b831c374ed033d0e466dc3c8711914a351be707"

  strings:
    $s1 = ",hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}