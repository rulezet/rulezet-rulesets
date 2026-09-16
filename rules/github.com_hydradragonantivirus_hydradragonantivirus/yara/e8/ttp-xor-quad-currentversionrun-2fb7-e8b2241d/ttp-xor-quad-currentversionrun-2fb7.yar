rule TTP_XOR_QUAD_CurrentVersionRun_2fb7 {
  strings:
    $key_2fb7 = { 7c d8 [2] 58 d6 [2] 73 fa [2] 5d d8 [2] 49 c3 [2] 46 d9 [2] 58 c4 [2] 5a c5 [2] 41 c3 [2] 5d c4 [2] 41 eb }

  condition:
    any of them
}