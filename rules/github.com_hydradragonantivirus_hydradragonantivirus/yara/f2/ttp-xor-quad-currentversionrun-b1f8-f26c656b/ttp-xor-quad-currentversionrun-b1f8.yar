rule TTP_XOR_QUAD_CurrentVersionRun_b1f8 {
  strings:
    $key_b1f8 = { e2 97 [2] c6 99 [2] ed b5 [2] c3 97 [2] d7 8c [2] d8 96 [2] c6 8b [2] c4 8a [2] df 8c [2] c3 8b [2] df a4 }

  condition:
    any of them
}