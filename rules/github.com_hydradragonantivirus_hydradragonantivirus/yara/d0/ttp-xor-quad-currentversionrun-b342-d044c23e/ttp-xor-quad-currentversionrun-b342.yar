rule TTP_XOR_QUAD_CurrentVersionRun_b342 {
  strings:
    $key_b342 = { e0 2d [2] c4 23 [2] ef 0f [2] c1 2d [2] d5 36 [2] da 2c [2] c4 31 [2] c6 30 [2] dd 36 [2] c1 31 [2] dd 1e }

  condition:
    any of them
}