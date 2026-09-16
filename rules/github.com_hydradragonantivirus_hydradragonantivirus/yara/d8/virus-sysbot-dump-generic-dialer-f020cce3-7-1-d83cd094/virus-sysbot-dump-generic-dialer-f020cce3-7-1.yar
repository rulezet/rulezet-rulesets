rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2df0780c18acf3d77a343f574ccf57dcffb8273f1ecffd316f6c2f83c6254db0"

  strings:
    $s1 = "kEUP:^^" fullword ascii
    $s2 = "h[cLOUT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}