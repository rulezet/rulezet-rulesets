rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da14276f97685256a7738c670c7e32438c67afde2752dba2a3aee37751e3e210"

  strings:
    $s1 = "bATs*'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}