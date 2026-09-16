rule TTP_XOR_QUAD_CurrentVersionRun_b3f1 {
  strings:
    $key_b3f1 = { e0 9e [2] c4 90 [2] ef bc [2] c1 9e [2] d5 85 [2] da 9f [2] c4 82 [2] c6 83 [2] dd 85 [2] c1 82 [2] dd ad }

  condition:
    any of them
}