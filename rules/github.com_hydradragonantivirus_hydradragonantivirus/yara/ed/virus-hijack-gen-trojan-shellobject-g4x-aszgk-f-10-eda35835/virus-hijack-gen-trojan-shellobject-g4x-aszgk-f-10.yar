rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a97f07f9143c16a1c204810e1c9c144de5535ffac8b5513f4712e8b267dbdcd0"

  strings:
    $s1 = "l_Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}