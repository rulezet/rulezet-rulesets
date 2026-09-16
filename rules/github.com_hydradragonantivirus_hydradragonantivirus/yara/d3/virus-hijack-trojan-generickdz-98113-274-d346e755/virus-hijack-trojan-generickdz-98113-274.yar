rule Virus_Hijack_Trojan_GenericKDZ_98113_274 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_274.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bad41a8d8300646ff0f7fe0882a866f2348303b17eca447c6415d22bebc1cb6"

  strings:
    $s1 = "K])TOHo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}