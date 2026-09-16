rule TTP_XOR_QUAD_CurrentVersionRun_b360 {
  strings:
    $key_b360 = { e0 0f [2] c4 01 [2] ef 2d [2] c1 0f [2] d5 14 [2] da 0e [2] c4 13 [2] c6 12 [2] dd 14 [2] c1 13 [2] dd 3c }

  condition:
    any of them
}