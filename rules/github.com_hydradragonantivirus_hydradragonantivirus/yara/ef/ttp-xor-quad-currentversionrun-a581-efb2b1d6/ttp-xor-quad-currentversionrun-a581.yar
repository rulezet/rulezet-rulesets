rule TTP_XOR_QUAD_CurrentVersionRun_a581 {
  strings:
    $key_a581 = { f6 ee [2] d2 e0 [2] f9 cc [2] d7 ee [2] c3 f5 [2] cc ef [2] d2 f2 [2] d0 f3 [2] cb f5 [2] d7 f2 [2] cb dd }

  condition:
    any of them
}