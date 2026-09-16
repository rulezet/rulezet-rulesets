rule TTP_XOR_QUAD_CurrentVersionRun_eeb7 {
  strings:
    $key_eeb7 = { bd d8 [2] 99 d6 [2] b2 fa [2] 9c d8 [2] 88 c3 [2] 87 d9 [2] 99 c4 [2] 9b c5 [2] 80 c3 [2] 9c c4 [2] 80 eb }

  condition:
    any of them
}