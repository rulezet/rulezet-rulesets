rule TTP_XOR_QUAD_CurrentVersionRun_b179 {
  strings:
    $key_b179 = { e2 16 [2] c6 18 [2] ed 34 [2] c3 16 [2] d7 0d [2] d8 17 [2] c6 0a [2] c4 0b [2] df 0d [2] c3 0a [2] df 25 }

  condition:
    any of them
}