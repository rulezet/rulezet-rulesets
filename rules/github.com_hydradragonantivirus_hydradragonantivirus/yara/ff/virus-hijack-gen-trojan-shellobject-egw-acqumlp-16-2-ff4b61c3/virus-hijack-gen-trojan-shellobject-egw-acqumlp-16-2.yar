rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_16_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f371fec1a2954e4431031fb20e0cdc6f548db545c0a211d930cd1f374ef3a70d"

  strings:
    $s1 = "Supreme" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}