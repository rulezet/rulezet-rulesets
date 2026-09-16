rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f6a915fb5e434b15a0d38096ac3e4e5f442a0f60c66ade92216eaf65953aa35"

  strings:
    $s1 = "7,purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}