rule TTP_XOR_QUAD_CurrentVersionRun_b1c6 {
  strings:
    $key_b1c6 = { e2 a9 [2] c6 a7 [2] ed 8b [2] c3 a9 [2] d7 b2 [2] d8 a8 [2] c6 b5 [2] c4 b4 [2] df b2 [2] c3 b5 [2] df 9a }

  condition:
    any of them
}