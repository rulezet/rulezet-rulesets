rule TTP_XOR_QUAD_CurrentVersionRun_b435 {
  strings:
    $key_b435 = { e7 5a [2] c3 54 [2] e8 78 [2] c6 5a [2] d2 41 [2] dd 5b [2] c3 46 [2] c1 47 [2] da 41 [2] c6 46 [2] da 69 }

  condition:
    any of them
}