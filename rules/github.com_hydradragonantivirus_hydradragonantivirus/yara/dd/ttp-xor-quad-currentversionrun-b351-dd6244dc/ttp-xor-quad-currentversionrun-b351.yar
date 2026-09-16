rule TTP_XOR_QUAD_CurrentVersionRun_b351 {
  strings:
    $key_b351 = { e0 3e [2] c4 30 [2] ef 1c [2] c1 3e [2] d5 25 [2] da 3f [2] c4 22 [2] c6 23 [2] dd 25 [2] c1 22 [2] dd 0d }

  condition:
    any of them
}