rule TTP_XOR_QUAD_CurrentVersionRun_3bb7 {
  strings:
    $key_3bb7 = { 68 d8 [2] 4c d6 [2] 67 fa [2] 49 d8 [2] 5d c3 [2] 52 d9 [2] 4c c4 [2] 4e c5 [2] 55 c3 [2] 49 c4 [2] 55 eb }

  condition:
    any of them
}