rule TTP_XOR_QUAD_CurrentVersionRun_b11b {
  strings:
    $key_b11b = { e2 74 [2] c6 7a [2] ed 56 [2] c3 74 [2] d7 6f [2] d8 75 [2] c6 68 [2] c4 69 [2] df 6f [2] c3 68 [2] df 47 }

  condition:
    any of them
}