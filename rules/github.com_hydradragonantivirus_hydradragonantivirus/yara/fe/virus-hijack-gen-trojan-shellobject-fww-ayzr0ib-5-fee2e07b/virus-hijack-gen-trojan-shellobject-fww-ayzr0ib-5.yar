rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7939654c43e34c73dfa5f9e78e46f29f4b131defe706ae72b4ec5d62894b312d"

  strings:
    $s1 = "3purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii
    $s2 = " z&YErn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}