rule TTP_XOR_QUAD_CurrentVersionRun_b37d {
  strings:
    $key_b37d = { e0 12 [2] c4 1c [2] ef 30 [2] c1 12 [2] d5 09 [2] da 13 [2] c4 0e [2] c6 0f [2] dd 09 [2] c1 0e [2] dd 21 }

  condition:
    any of them
}