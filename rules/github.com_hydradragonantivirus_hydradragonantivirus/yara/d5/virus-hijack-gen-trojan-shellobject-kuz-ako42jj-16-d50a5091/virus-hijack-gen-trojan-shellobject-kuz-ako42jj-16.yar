rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e704d08f218d3c0e0741d6aab6dfe08c49f4bd46eb796b062507317c2ff57769"

  strings:
    $s1 = "oofY#<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}