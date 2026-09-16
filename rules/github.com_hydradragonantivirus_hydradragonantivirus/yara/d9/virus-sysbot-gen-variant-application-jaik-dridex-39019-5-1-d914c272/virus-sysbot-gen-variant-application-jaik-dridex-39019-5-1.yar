rule Virus_Sysbot_Gen_Variant_Application_Jaik_Dridex_39019_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Application.Jaik.Dridex.39019_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd745645b7f855c6646b201b757ef6a9d0bdadd153a3032bb4a4efb39c087702"

  strings:
    $s1 = "wOTe)(-" fullword ascii
    $s2 = "KO mOAN$#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}