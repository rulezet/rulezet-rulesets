rule TTP_XOR_QUAD_CurrentVersionRun_6ab7 {
  strings:
    $key_6ab7 = { 39 d8 [2] 1d d6 [2] 36 fa [2] 18 d8 [2] 0c c3 [2] 03 d9 [2] 1d c4 [2] 1f c5 [2] 04 c3 [2] 18 c4 [2] 04 eb }

  condition:
    any of them
}