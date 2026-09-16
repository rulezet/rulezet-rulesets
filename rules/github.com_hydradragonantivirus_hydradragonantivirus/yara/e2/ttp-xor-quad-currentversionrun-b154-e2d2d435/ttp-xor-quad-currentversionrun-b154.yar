rule TTP_XOR_QUAD_CurrentVersionRun_b154 {
  strings:
    $key_b154 = { e2 3b [2] c6 35 [2] ed 19 [2] c3 3b [2] d7 20 [2] d8 3a [2] c6 27 [2] c4 26 [2] df 20 [2] c3 27 [2] df 08 }

  condition:
    any of them
}