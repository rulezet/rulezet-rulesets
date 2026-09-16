rule TTP_XOR_QUAD_CurrentVersionRun_b7b7 {
  strings:
    $key_b7b7 = { e4 d8 [2] c0 d6 [2] eb fa [2] c5 d8 [2] d1 c3 [2] de d9 [2] c0 c4 [2] c2 c5 [2] d9 c3 [2] c5 c4 [2] d9 eb }

  condition:
    any of them
}