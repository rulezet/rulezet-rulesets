rule Virus_Hijack_Gen_Trojan_ShellObject_i0Y_amFE__j_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e55953f081dcca78557a5b8be0a7015b828b8ad013f3470ee4e432c7897f340"

  strings:
    $s1 = "Distribucjx Transaction Coordinator Service." fullword ascii
    $s2 = "Distribufqy Transaction Coordinator Service" fullword ascii
    $s3 = "server " fullword wide
    $s4 = "server Microsoft " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}