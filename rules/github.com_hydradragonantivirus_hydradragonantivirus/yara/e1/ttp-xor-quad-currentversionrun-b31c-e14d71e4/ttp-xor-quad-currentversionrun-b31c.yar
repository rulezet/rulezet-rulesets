rule TTP_XOR_QUAD_CurrentVersionRun_b31c {
  strings:
    $key_b31c = { e0 73 [2] c4 7d [2] ef 51 [2] c1 73 [2] d5 68 [2] da 72 [2] c4 6f [2] c6 6e [2] dd 68 [2] c1 6f [2] dd 40 }

  condition:
    any of them
}