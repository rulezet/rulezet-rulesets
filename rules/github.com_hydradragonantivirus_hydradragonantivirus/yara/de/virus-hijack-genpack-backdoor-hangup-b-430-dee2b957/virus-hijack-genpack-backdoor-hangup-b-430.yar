rule Virus_Hijack_GenPack_Backdoor_Hangup_B_430 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_430.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27e1a04bead72d2c8e3c29f57b0dddda07e1e86e6534b70a732f62fdc16d6093"

  strings:
    $s1 = "Psoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}