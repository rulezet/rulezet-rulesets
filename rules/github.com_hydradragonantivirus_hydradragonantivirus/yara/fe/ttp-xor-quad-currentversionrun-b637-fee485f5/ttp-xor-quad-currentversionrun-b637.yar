rule TTP_XOR_QUAD_CurrentVersionRun_b637 {
  strings:
    $key_b637 = { e5 58 [2] c1 56 [2] ea 7a [2] c4 58 [2] d0 43 [2] df 59 [2] c1 44 [2] c3 45 [2] d8 43 [2] c4 44 [2] d8 6b }

  condition:
    any of them
}