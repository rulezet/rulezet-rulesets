rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "069921968f012c1fff15af7a33823219057b127409d66798c7faeaced8e6dc85"

  strings:
    $s1 = "Zpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}