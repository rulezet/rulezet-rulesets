rule TTP_XOR_QUAD_CurrentVersionRun_b4e7 {
  strings:
    $key_b4e7 = { e7 88 [2] c3 86 [2] e8 aa [2] c6 88 [2] d2 93 [2] dd 89 [2] c3 94 [2] c1 95 [2] da 93 [2] c6 94 [2] da bb }

  condition:
    any of them
}