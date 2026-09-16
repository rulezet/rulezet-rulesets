rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3043e3e185f1e935c2a7c24c6fd110e45428054bfc0715151d116ca7baed5a8"

  strings:
    $s1 = "Iavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}