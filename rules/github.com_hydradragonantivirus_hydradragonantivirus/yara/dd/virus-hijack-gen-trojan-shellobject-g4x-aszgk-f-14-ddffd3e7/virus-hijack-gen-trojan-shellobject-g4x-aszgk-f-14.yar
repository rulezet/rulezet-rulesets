rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa70c9a44229b0defe5640fef41e0284c2ff6eb5580746c4f4b99ca4a73ea72d"

  strings:
    $s1 = "qOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}