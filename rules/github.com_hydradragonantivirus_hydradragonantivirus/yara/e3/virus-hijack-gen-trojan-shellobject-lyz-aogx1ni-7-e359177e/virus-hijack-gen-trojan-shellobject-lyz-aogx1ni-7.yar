rule Virus_Hijack_Gen_Trojan_ShellObject_lyZ_aOgx1ni_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lyZ@aOgx1ni_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edd9591cdee85a13fd3da4a1b9220b87c7c1ec1be671bb6764591f0ccb950d6d"

  strings:
    $s1 = "<description>msoasb</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}