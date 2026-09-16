rule TTP_XOR_QUAD_CurrentVersionRun_b134 {
  strings:
    $key_b134 = { e2 5b [2] c6 55 [2] ed 79 [2] c3 5b [2] d7 40 [2] d8 5a [2] c6 47 [2] c4 46 [2] df 40 [2] c3 47 [2] df 68 }

  condition:
    any of them
}