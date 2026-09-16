rule TTP_XOR_QUAD_CurrentVersionRun_3ab7 {
  strings:
    $key_3ab7 = { 69 d8 [2] 4d d6 [2] 66 fa [2] 48 d8 [2] 5c c3 [2] 53 d9 [2] 4d c4 [2] 4f c5 [2] 54 c3 [2] 48 c4 [2] 54 eb }

  condition:
    any of them
}