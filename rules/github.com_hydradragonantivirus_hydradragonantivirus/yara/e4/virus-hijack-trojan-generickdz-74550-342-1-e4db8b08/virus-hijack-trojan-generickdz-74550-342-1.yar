rule Virus_Hijack_Trojan_GenericKDZ_74550_342_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_342_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45166e90510a3f8b972f5f723c3bc909cb7ebe09f29468feb0f07ead5ff922a5"

  strings:
    $s1 = "L APIo]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}