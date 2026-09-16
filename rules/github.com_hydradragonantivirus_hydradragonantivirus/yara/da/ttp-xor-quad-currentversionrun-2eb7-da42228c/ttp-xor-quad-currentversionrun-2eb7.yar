rule TTP_XOR_QUAD_CurrentVersionRun_2eb7 {
  strings:
    $key_2eb7 = { 7d d8 [2] 59 d6 [2] 72 fa [2] 5c d8 [2] 48 c3 [2] 47 d9 [2] 59 c4 [2] 5b c5 [2] 40 c3 [2] 5c c4 [2] 40 eb }

  condition:
    any of them
}