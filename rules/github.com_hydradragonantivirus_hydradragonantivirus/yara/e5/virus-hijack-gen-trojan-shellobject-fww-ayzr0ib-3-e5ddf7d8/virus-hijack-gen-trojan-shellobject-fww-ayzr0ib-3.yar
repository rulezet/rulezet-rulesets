rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b336a984d7a55a3a92fd62d56a684009121de11a66f4102cff666d5fc20d9861"

  strings:
    $s1 = "a:purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}