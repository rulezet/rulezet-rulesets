rule TTP_XOR_QUAD_CurrentVersionRun_b777 {
  strings:
    $key_b777 = { e4 18 [2] c0 16 [2] eb 3a [2] c5 18 [2] d1 03 [2] de 19 [2] c0 04 [2] c2 05 [2] d9 03 [2] c5 04 [2] d9 2b }

  condition:
    any of them
}