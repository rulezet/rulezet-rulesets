rule TTP_XOR_QUAD_CurrentVersionRun_74b7 {
  strings:
    $key_74b7 = { 27 d8 [2] 03 d6 [2] 28 fa [2] 06 d8 [2] 12 c3 [2] 1d d9 [2] 03 c4 [2] 01 c5 [2] 1a c3 [2] 06 c4 [2] 1a eb }

  condition:
    any of them
}