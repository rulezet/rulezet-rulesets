rule TTP_XOR_QUAD_CurrentVersionRun_97a7 {
  strings:
    $key_97a7 = { c4 c8 [2] e0 c6 [2] cb ea [2] e5 c8 [2] f1 d3 [2] fe c9 [2] e0 d4 [2] e2 d5 [2] f9 d3 [2] e5 d4 [2] f9 fb }

  condition:
    any of them
}