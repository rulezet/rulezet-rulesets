rule TTP_XOR_QUAD_CurrentVersionRun_49b7 {
  strings:
    $key_49b7 = { 1a d8 [2] 3e d6 [2] 15 fa [2] 3b d8 [2] 2f c3 [2] 20 d9 [2] 3e c4 [2] 3c c5 [2] 27 c3 [2] 3b c4 [2] 27 eb }

  condition:
    any of them
}