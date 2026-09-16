rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_aG7qmhc_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@aG7qmhc_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fab0d07db8e3ec5d5334072b727d4f0425e75d09638c8fe5afe57e89033a0ae6"

  strings:
    $s1 = "tHEw}=PyV" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}