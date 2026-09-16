rule Virus_Hijack_Gen_Trojan_ShellObject_pzZ_aCEmdoo_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pzZ@aCEmdoo_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8999429955731a0ae6cb68a253d56ad0d8f5bc02aca444c35a165ab53d523c79"

  strings:
    $s1 = "Hemp]1E" fullword ascii
    $s2 = "p$halO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}