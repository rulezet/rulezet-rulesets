rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f515cb65a95117782f3953a4e40d8148d8e32a9c685f801b81cab959abec99b8"

  strings:
    $s1 = "Kpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}