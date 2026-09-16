rule TTP_XOR_QUAD_CurrentVersionRun_b35b {
  strings:
    $key_b35b = { e0 34 [2] c4 3a [2] ef 16 [2] c1 34 [2] d5 2f [2] da 35 [2] c4 28 [2] c6 29 [2] dd 2f [2] c1 28 [2] dd 07 }

  condition:
    any of them
}