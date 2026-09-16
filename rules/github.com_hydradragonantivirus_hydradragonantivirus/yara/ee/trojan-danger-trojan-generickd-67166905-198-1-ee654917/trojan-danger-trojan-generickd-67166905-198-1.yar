rule Trojan_Danger_Trojan_GenericKD_67166905_198_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_198_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df0c05975aa7aed7cfd6d1a25f24207fd0d1362bd35bc59a6b20e7fff05277a"

  strings:
    $s1 = " available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}