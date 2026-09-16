rule TTP_XOR_QUAD_CurrentVersionRun_89bb {
  strings:
    $key_89bb = { da d4 [2] fe da [2] d5 f6 [2] fb d4 [2] ef cf [2] e0 d5 [2] fe c8 [2] fc c9 [2] e7 cf [2] fb c8 [2] e7 e7 }

  condition:
    any of them
}