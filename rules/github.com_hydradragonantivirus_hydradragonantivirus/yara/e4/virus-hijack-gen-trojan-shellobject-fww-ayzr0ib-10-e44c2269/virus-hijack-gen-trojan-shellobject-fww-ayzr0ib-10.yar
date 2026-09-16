rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b176b2a9284222a24acea8792c0ff0778f3f3c6665c5e26db3b0857ca0568e6a"

  strings:
    $s1 = "y&purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}