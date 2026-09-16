rule TTP_XOR_QUAD_CurrentVersionRun_b3c7 {
  strings:
    $key_b3c7 = { e0 a8 [2] c4 a6 [2] ef 8a [2] c1 a8 [2] d5 b3 [2] da a9 [2] c4 b4 [2] c6 b5 [2] dd b3 [2] c1 b4 [2] dd 9b }

  condition:
    any of them
}