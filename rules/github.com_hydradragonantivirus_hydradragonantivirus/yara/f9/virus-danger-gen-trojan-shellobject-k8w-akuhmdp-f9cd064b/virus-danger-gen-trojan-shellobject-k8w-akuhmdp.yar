rule Virus_Danger_Gen_Trojan_ShellObject_k8W_aKuHmDp {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.k8W@aKuHmDp.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d9ea515888d8bcb48d047a8aeb24bcb7a323a14ed3640e427003579f38355bc"

  strings:
    $s1 = "2>iDle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}