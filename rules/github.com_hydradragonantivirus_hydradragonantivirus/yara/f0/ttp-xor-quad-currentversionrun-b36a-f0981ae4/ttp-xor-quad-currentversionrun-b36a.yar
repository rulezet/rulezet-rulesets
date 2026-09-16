rule TTP_XOR_QUAD_CurrentVersionRun_b36a {
  strings:
    $key_b36a = { e0 05 [2] c4 0b [2] ef 27 [2] c1 05 [2] d5 1e [2] da 04 [2] c4 19 [2] c6 18 [2] dd 1e [2] c1 19 [2] dd 36 }

  condition:
    any of them
}