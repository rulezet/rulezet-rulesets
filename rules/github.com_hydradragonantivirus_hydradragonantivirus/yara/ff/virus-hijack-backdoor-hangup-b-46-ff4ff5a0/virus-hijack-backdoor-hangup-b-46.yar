rule Virus_Hijack_Backdoor_Hangup_B_46 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed85478733b3bb0f343a7fcdc2b9e86c53deafa5bb698898b5afc60897177fbd"

  strings:
    $s1 = "jimP%i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}