rule TTP_XOR_QUAD_CurrentVersionRun_b417 {
  strings:
    $key_b417 = { e7 78 [2] c3 76 [2] e8 5a [2] c6 78 [2] d2 63 [2] dd 79 [2] c3 64 [2] c1 65 [2] da 63 [2] c6 64 [2] da 4b }

  condition:
    any of them
}