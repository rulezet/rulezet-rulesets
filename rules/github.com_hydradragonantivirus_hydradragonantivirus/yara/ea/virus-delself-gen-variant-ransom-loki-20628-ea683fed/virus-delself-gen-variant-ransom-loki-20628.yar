rule Virus_Delself_Gen_Variant_Ransom_Loki_20628 {
  meta:
    description = "datamaliciousorder - file Virus.Delself_Gen.Variant.Ransom.Loki.20628.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f9e39c7269283ae2350f65419a89f11b8199ef09a3457f09b673f3100d93200"

  strings:
    $s1 = "(unnamed password)" fullword ascii
    $s2 = "Portions Copyright (c) 1999,2003 Avenger by NhT" fullword ascii
    $s3 = "(unnamed value)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}