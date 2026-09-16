rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa55ead220b36337820e9e93bcf367058ce7fffad27337effcf64b6779a89d31"

  strings:
    $s1 = "About HanAgent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}