rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aOWVavp_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08f1759378b4d0e487cb4569793bea7df88555ce27d7d2f2555c6c476debade6"

  strings:
    $s1 = "hT@MonK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}