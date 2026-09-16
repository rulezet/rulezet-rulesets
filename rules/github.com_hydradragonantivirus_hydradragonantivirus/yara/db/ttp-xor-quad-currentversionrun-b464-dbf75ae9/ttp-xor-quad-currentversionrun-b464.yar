rule TTP_XOR_QUAD_CurrentVersionRun_b464 {
  strings:
    $key_b464 = { e7 0b [2] c3 05 [2] e8 29 [2] c6 0b [2] d2 10 [2] dd 0a [2] c3 17 [2] c1 16 [2] da 10 [2] c6 17 [2] da 38 }

  condition:
    any of them
}