rule Virus_Hijack_Trojan_GenericKDZ_98113_190_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_190_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f949f534dd4fa9daeb1b2988a2f823d304497e3d11cca0031e8d38aa092fbb42"

  strings:
    $s1 = "c]ACId" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}