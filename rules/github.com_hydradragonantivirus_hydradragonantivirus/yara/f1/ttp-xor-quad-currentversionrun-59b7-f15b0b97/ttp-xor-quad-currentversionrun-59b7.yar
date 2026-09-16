rule TTP_XOR_QUAD_CurrentVersionRun_59b7 {
  strings:
    $key_59b7 = { 0a d8 [2] 2e d6 [2] 05 fa [2] 2b d8 [2] 3f c3 [2] 30 d9 [2] 2e c4 [2] 2c c5 [2] 37 c3 [2] 2b c4 [2] 37 eb }

  condition:
    any of them
}