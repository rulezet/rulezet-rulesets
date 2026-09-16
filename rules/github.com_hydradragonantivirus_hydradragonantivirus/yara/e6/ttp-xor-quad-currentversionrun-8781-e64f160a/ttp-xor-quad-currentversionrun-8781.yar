rule TTP_XOR_QUAD_CurrentVersionRun_8781 {
  strings:
    $key_8781 = { d4 ee [2] f0 e0 [2] db cc [2] f5 ee [2] e1 f5 [2] ee ef [2] f0 f2 [2] f2 f3 [2] e9 f5 [2] f5 f2 [2] e9 dd }

  condition:
    any of them
}