rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16e3011f3a50620b769c6dbea714266bafefaf0b54fb64c0ff1d92461e991517"

  strings:
    $s1 = "6Ppurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}