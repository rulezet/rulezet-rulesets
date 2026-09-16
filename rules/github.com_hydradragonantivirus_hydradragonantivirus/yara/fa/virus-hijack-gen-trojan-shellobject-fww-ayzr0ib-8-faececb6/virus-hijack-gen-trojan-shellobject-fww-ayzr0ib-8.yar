rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41cefea1b7cc330d98cc25a19e77e82d5651a26c9cb8604f3747461b1f694908"

  strings:
    $s1 = ")3purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}