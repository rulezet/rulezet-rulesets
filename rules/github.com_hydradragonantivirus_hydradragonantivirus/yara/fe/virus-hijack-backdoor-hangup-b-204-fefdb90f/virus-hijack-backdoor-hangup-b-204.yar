rule Virus_Hijack_Backdoor_Hangup_B_204 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_204.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3f73fabd80fadb9ae84342be861a4e4135057201fbeeaaba1961b8a6634749e"

  strings:
    $s1 = "Qsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}