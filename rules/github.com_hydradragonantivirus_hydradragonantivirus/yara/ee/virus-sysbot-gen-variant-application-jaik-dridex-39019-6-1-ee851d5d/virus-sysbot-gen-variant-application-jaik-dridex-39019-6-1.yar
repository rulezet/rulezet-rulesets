rule Virus_Sysbot_Gen_Variant_Application_Jaik_Dridex_39019_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Gen.Variant.Application.Jaik.Dridex.39019_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85286c6cfdcacc8443427903fe3801352deca7346f5fa953cdf493fb5c9c4c80"

  strings:
    $s1 = "fiLl*FJ " fullword ascii
    $s2 = "O,g`sYNC" fullword ascii
    $s3 = "'?ReIf" fullword ascii
    $s4 = "T1}cyME" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}