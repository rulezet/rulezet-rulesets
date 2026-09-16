rule Trojan_Danger_Trojan_GenericKD_67166905_158_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_158_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3514da64802f2766aa86a997c40ce782ec001bd68ac3cfd6e0090e602ad6d377"

  strings:
    $s1 = ")available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}