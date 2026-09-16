rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_aiy413e_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b31bd2b2fbd65040ca4ad69e4f74252d24f99d93061e842cc5e5705798ca474"

  strings:
    $s1 = "no,BlIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}