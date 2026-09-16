rule Virus_Hijack_Gen_Trojan_ShellObject_g4X_aSzGK_f_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3d3ec3ddecab10f6c06bd0f8297ac26fd81bf48ddb0f757fd31c4152d1da239"

  strings:
    $s1 = "yOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}