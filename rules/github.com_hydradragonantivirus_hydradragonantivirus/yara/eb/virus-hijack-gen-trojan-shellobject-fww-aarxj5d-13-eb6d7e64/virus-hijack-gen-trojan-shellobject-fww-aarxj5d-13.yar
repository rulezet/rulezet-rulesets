rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5457f9d3f6b94531f5402f48e75f342acdc0feff493bd1960e34677d5ac35ea4"

  strings:
    $s1 = "vpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}