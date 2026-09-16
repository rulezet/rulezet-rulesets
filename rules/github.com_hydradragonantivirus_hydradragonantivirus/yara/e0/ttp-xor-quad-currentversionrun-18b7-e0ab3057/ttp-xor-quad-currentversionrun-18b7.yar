rule TTP_XOR_QUAD_CurrentVersionRun_18b7 {
  strings:
    $key_18b7 = { 4b d8 [2] 6f d6 [2] 44 fa [2] 6a d8 [2] 7e c3 [2] 71 d9 [2] 6f c4 [2] 6d c5 [2] 76 c3 [2] 6a c4 [2] 76 eb }

  condition:
    any of them
}