rule TTP_XOR_QUAD_CurrentVersionRun_b767 {
  strings:
    $key_b767 = { e4 08 [2] c0 06 [2] eb 2a [2] c5 08 [2] d1 13 [2] de 09 [2] c0 14 [2] c2 15 [2] d9 13 [2] c5 14 [2] d9 3b }

  condition:
    any of them
}