rule TTP_XOR_QUAD_CurrentVersionRun_b448 {
  strings:
    $key_b448 = { e7 27 [2] c3 29 [2] e8 05 [2] c6 27 [2] d2 3c [2] dd 26 [2] c3 3b [2] c1 3a [2] da 3c [2] c6 3b [2] da 14 }

  condition:
    any of them
}