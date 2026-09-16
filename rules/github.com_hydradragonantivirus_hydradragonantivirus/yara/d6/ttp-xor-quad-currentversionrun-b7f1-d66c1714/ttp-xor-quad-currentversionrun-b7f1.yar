rule TTP_XOR_QUAD_CurrentVersionRun_b7f1 {
  strings:
    $key_b7f1 = { e4 9e [2] c0 90 [2] eb bc [2] c5 9e [2] d1 85 [2] de 9f [2] c0 82 [2] c2 83 [2] d9 85 [2] c5 82 [2] d9 ad }

  condition:
    any of them
}