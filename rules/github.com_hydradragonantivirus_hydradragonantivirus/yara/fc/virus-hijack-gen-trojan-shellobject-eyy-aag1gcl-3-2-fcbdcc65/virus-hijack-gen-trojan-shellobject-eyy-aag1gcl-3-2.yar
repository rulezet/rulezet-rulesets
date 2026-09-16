rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aag1Gcl_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aag1Gcl_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54e823e778135245e1ac095fd6af3320dc8235dfdb1f973144ecb5a532ac45a6"

  strings:
    $s1 = "?$SifT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}