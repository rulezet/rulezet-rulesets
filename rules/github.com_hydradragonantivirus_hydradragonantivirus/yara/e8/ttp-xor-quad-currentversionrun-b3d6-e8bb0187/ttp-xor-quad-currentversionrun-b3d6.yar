rule TTP_XOR_QUAD_CurrentVersionRun_b3d6 {
  strings:
    $key_b3d6 = { e0 b9 [2] c4 b7 [2] ef 9b [2] c1 b9 [2] d5 a2 [2] da b8 [2] c4 a5 [2] c6 a4 [2] dd a2 [2] c1 a5 [2] dd 8a }

  condition:
    any of them
}