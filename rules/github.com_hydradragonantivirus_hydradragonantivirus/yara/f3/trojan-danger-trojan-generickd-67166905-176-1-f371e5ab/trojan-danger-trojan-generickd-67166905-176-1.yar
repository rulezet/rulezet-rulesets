rule Trojan_Danger_Trojan_GenericKD_67166905_176_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_176_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50c3aca4be6d046fa5f9f4e3f8b66c13b123115ad98c196f711be5b3bcd6ca59"

  strings:
    $s1 = "jpOracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}