rule Virus_Sysbot_Dump_Generic_Dialer_34ECF9D6_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.34ECF9D6_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df0231d37d5d9a337b600e80f2473447bceca929d7b3af92ef355517bbe9978d"

  strings:
    $s1 = "?NiTO@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}