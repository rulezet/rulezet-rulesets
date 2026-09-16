rule TTP_XOR_QUAD_CurrentVersionRun_b3c6 {
  strings:
    $key_b3c6 = { e0 a9 [2] c4 a7 [2] ef 8b [2] c1 a9 [2] d5 b2 [2] da a8 [2] c4 b5 [2] c6 b4 [2] dd b2 [2] c1 b5 [2] dd 9a }

  condition:
    any of them
}