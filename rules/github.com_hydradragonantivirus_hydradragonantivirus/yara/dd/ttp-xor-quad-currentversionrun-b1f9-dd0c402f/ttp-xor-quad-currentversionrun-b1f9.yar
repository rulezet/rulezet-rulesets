rule TTP_XOR_QUAD_CurrentVersionRun_b1f9 {
  strings:
    $key_b1f9 = { e2 96 [2] c6 98 [2] ed b4 [2] c3 96 [2] d7 8d [2] d8 97 [2] c6 8a [2] c4 8b [2] df 8d [2] c3 8a [2] df a5 }

  condition:
    any of them
}