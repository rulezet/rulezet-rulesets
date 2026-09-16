rule TTP_XOR_QUAD_CurrentVersionRun_6eb7 {
  strings:
    $key_6eb7 = { 3d d8 [2] 19 d6 [2] 32 fa [2] 1c d8 [2] 08 c3 [2] 07 d9 [2] 19 c4 [2] 1b c5 [2] 00 c3 [2] 1c c4 [2] 00 eb }

  condition:
    any of them
}