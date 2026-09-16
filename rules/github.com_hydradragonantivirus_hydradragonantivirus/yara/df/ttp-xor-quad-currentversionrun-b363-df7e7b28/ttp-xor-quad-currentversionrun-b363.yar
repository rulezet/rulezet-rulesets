rule TTP_XOR_QUAD_CurrentVersionRun_b363 {
  strings:
    $key_b363 = { e0 0c [2] c4 02 [2] ef 2e [2] c1 0c [2] d5 17 [2] da 0d [2] c4 10 [2] c6 11 [2] dd 17 [2] c1 10 [2] dd 3f }

  condition:
    any of them
}