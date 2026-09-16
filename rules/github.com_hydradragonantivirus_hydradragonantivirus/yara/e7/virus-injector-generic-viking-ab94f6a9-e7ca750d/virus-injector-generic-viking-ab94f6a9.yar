rule Virus_Injector_Generic_Viking_AB94F6A9 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.AB94F6A9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cea9cadd842f36c80e051ed4cbd759e6269674d54ef65ec7056b5ac71ee4913"

  strings:
    $s1 = "Google Update Core" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}