rule Virus_Hijack_Trojan_GenericKDZ_103285_688_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_688_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e7fcb79c5051540cd97d218e986a9169dc9f6073e18e5ad4797688ae9546986"

  strings:
    $s1 = "2.1 Default RGB colour space " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}