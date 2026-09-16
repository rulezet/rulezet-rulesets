rule Virus_Hijack_Backdoor_Hangup_B_69_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eaecb4a746375b1314677b929c8bc339893c852b5f18f4769aa4498dff0721d"

  strings:
    $s1 = "Software\\Ghisler\\Windows Commander" fullword ascii
    $s2 = "Software\\Ghisler\\Total Commander" fullword ascii
    $s3 = "--begin--" fullword ascii
    $s4 = "Add to kill %s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}