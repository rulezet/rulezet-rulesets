rule Virus_Hijack_Trojan_GenericKDZ_74550_94_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_94_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d433b4834fff5811c05b5c3aa014245552b584d558e9645a3f0a08e9623c61f0"

  strings:
    $s1 = "UE{thiS }[FOY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}