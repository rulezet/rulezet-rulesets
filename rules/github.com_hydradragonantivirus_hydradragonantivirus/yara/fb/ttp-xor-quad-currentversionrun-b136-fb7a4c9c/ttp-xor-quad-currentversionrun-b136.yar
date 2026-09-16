rule TTP_XOR_QUAD_CurrentVersionRun_b136 {
  strings:
    $key_b136 = { e2 59 [2] c6 57 [2] ed 7b [2] c3 59 [2] d7 42 [2] d8 58 [2] c6 45 [2] c4 44 [2] df 42 [2] c3 45 [2] df 6a }

  condition:
    any of them
}