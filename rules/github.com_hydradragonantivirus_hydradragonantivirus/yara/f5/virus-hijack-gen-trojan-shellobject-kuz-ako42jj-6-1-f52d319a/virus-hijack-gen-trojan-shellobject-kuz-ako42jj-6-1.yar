rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0bb77682c3ac102f07a64bc99955122fa87189bde2f37876f40565f8a050364"

  strings:
    $s1 = "soft Visual StudQn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}