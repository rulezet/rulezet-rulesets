rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_43 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_43.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23cd548a9e720a5815c0fd62b4531686570bb2786e7afd983b8a0ca7b1a67f61"

  strings:
    $s1 = "agog R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}