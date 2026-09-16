rule Virus_Hijack_Trojan_GenericKDZ_98113_279 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_279.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a68a77eae4e8b575a9dc1ec95f587ec0b4a5572b10624cd50c850a7b953ba9e6"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "ptimizer': None, @^U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}