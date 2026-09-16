rule TTP_XOR_QUAD_CurrentVersionRun_b416 {
  strings:
    $key_b416 = { e7 79 [2] c3 77 [2] e8 5b [2] c6 79 [2] d2 62 [2] dd 78 [2] c3 65 [2] c1 64 [2] da 62 [2] c6 65 [2] da 4a }

  condition:
    any of them
}