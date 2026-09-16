rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98933c4dfb0ffa2b7ba283759dd4bcbb87d477250c7a0f8fbfcb5853f2a199cb"

  strings:
    $s1 = "Some more data" fullword wide
    $s2 = "Fighting for bad" fullword wide
    $s3 = "Fighting for good" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}