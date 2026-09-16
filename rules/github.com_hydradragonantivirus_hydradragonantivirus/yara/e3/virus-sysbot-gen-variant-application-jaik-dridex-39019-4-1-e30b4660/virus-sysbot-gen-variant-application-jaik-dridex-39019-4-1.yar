rule Virus_Sysbot_Gen_Variant_Application_Jaik_Dridex_39019_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Application.Jaik.Dridex.39019_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b35017d89b7ac3b07bc4e87c6ac6e45ba596d805b9619de4a5b63ba04145621"

  strings:
    $s1 = "KUdU`E7" fullword ascii
    $s2 = "]&NAUt" fullword ascii
    $s3 = "`HoLt{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}