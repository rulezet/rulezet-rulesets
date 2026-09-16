rule TTP_XOR_QUAD_CurrentVersionRun_b450 {
  strings:
    $key_b450 = { e7 3f [2] c3 31 [2] e8 1d [2] c6 3f [2] d2 24 [2] dd 3e [2] c3 23 [2] c1 22 [2] da 24 [2] c6 23 [2] da 0c }

  condition:
    any of them
}