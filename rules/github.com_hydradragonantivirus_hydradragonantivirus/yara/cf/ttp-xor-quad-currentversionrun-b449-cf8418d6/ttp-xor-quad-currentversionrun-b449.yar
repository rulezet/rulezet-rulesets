rule TTP_XOR_QUAD_CurrentVersionRun_b449 {
  strings:
    $key_b449 = { e7 26 [2] c3 28 [2] e8 04 [2] c6 26 [2] d2 3d [2] dd 27 [2] c3 3a [2] c1 3b [2] da 3d [2] c6 3a [2] da 15 }

  condition:
    any of them
}