rule TTP_XOR_QUAD_CurrentVersionRun_b1f4 {
  strings:
    $key_b1f4 = { e2 9b [2] c6 95 [2] ed b9 [2] c3 9b [2] d7 80 [2] d8 9a [2] c6 87 [2] c4 86 [2] df 80 [2] c3 87 [2] df a8 }

  condition:
    any of them
}