rule Virus_Hijack_Trojan_GenericKDZ_98113_222_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_222_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bf37fe0d90121397ddc32d860750296170f450aa9014b19b6183c006510aadc"

  strings:
    $s1 = "4}CrUm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}