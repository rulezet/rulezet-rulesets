rule TTP_XOR_QUAD_CurrentVersionRun_b372 {
  strings:
    $key_b372 = { e0 1d [2] c4 13 [2] ef 3f [2] c1 1d [2] d5 06 [2] da 1c [2] c4 01 [2] c6 00 [2] dd 06 [2] c1 01 [2] dd 2e }

  condition:
    any of them
}