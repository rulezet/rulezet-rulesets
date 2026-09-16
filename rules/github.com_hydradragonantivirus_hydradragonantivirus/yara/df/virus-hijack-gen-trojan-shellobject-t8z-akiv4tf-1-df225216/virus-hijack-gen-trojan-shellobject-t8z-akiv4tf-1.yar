rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKiV4Tf_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKiV4Tf_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44364ac9b0e059939d168c1e0e179927c15fe6a1491f0a00604d05bf7a1d9cce"

  strings:
    $s1 = "0!virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}