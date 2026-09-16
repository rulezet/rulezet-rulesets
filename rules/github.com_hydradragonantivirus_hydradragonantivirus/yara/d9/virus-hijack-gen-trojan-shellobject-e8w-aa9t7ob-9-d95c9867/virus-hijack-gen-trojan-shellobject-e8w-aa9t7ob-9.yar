rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "863339ef739b30d0c2b534891a1f3f85a8cff60690a3ca2837026c68dbee18db"

  strings:
    $s1 = "7hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}