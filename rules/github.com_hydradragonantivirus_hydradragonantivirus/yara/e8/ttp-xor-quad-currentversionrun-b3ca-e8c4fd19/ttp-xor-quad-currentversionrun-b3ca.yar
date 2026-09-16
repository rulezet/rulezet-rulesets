rule TTP_XOR_QUAD_CurrentVersionRun_b3ca {
  strings:
    $key_b3ca = { e0 a5 [2] c4 ab [2] ef 87 [2] c1 a5 [2] d5 be [2] da a4 [2] c4 b9 [2] c6 b8 [2] dd be [2] c1 b9 [2] dd 96 }

  condition:
    any of them
}