rule TTP_XOR_QUAD_CurrentVersionRun_a7b7 {
  strings:
    $key_a7b7 = { f4 d8 [2] d0 d6 [2] fb fa [2] d5 d8 [2] c1 c3 [2] ce d9 [2] d0 c4 [2] d2 c5 [2] c9 c3 [2] d5 c4 [2] c9 eb }

  condition:
    any of them
}