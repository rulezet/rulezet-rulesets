rule Virus_Hijack_Trojan_GenericKDZ_98113_160_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_160_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6e08be3577abdbebea662e4203864d43508a50584b48bfcad4231cce32306a1"

  strings:
    $s1 = "%d#TiNE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}