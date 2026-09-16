rule TTP_XOR_QUAD_CurrentVersionRun_1db7 {
  strings:
    $key_1db7 = { 4e d8 [2] 6a d6 [2] 41 fa [2] 6f d8 [2] 7b c3 [2] 74 d9 [2] 6a c4 [2] 68 c5 [2] 73 c3 [2] 6f c4 [2] 73 eb }

  condition:
    any of them
}