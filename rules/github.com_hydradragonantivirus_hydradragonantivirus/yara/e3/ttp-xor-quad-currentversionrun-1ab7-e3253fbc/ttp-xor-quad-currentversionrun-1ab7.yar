rule TTP_XOR_QUAD_CurrentVersionRun_1ab7 {
  strings:
    $key_1ab7 = { 49 d8 [2] 6d d6 [2] 46 fa [2] 68 d8 [2] 7c c3 [2] 73 d9 [2] 6d c4 [2] 6f c5 [2] 74 c3 [2] 68 c4 [2] 74 eb }

  condition:
    any of them
}