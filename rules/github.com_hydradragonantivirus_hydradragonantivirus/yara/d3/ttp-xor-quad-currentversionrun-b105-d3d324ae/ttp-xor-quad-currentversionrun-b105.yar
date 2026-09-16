rule TTP_XOR_QUAD_CurrentVersionRun_b105 {
  strings:
    $key_b105 = { e2 6a [2] c6 64 [2] ed 48 [2] c3 6a [2] d7 71 [2] d8 6b [2] c6 76 [2] c4 77 [2] df 71 [2] c3 76 [2] df 59 }

  condition:
    any of them
}