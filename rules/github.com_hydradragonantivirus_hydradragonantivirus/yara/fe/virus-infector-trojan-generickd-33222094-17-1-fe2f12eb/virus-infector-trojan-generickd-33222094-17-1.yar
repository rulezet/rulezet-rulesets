rule Virus_Infector_Trojan_GenericKD_33222094_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Trojan.GenericKD.33222094_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb7e168f65afe962adaf4a8f01b76b248da4d90561856d73b68c34aa059f73a7"

  strings:
    $s1 = "g Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference Viewi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}