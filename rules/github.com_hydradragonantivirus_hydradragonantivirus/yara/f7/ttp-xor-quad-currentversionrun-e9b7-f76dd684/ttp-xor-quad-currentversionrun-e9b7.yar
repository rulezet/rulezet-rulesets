rule TTP_XOR_QUAD_CurrentVersionRun_e9b7 {
  strings:
    $key_e9b7 = { ba d8 [2] 9e d6 [2] b5 fa [2] 9b d8 [2] 8f c3 [2] 80 d9 [2] 9e c4 [2] 9c c5 [2] 87 c3 [2] 9b c4 [2] 87 eb }

  condition:
    any of them
}