rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_70_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e25aa59e5a1511cd5ec65b272fbfaa61ea1fbbf0aa506d35bc319c91fd8659d3"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "ptimizer': None, @^U" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}