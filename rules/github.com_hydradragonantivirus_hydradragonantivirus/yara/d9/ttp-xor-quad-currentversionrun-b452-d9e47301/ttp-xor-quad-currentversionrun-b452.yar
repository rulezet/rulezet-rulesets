rule TTP_XOR_QUAD_CurrentVersionRun_b452 {
  strings:
    $key_b452 = { e7 3d [2] c3 33 [2] e8 1f [2] c6 3d [2] d2 26 [2] dd 3c [2] c3 21 [2] c1 20 [2] da 26 [2] c6 21 [2] da 0e }

  condition:
    any of them
}