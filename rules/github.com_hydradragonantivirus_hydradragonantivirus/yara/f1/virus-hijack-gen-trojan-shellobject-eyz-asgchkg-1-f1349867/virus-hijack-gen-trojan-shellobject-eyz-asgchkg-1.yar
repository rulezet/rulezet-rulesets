rule Virus_Hijack_Gen_Trojan_ShellObject_EyZ_aSgChKg_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EyZ@aSgChKg_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "991fbf58b186af74b201e537af6e25295d1a52df808f1c9036b358b68bd12554"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "ptimizer': None, @^U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}