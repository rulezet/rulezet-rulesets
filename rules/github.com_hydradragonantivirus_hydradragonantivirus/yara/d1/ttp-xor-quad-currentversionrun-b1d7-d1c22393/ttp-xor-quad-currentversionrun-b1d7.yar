rule TTP_XOR_QUAD_CurrentVersionRun_b1d7 {
  strings:
    $key_b1d7 = { e2 b8 [2] c6 b6 [2] ed 9a [2] c3 b8 [2] d7 a3 [2] d8 b9 [2] c6 a4 [2] c4 a5 [2] df a3 [2] c3 a4 [2] df 8b }

  condition:
    any of them
}