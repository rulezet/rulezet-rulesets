rule TTP_XOR_QUAD_CurrentVersionRun_b45e {
  strings:
    $key_b45e = { e7 31 [2] c3 3f [2] e8 13 [2] c6 31 [2] d2 2a [2] dd 30 [2] c3 2d [2] c1 2c [2] da 2a [2] c6 2d [2] da 02 }

  condition:
    any of them
}