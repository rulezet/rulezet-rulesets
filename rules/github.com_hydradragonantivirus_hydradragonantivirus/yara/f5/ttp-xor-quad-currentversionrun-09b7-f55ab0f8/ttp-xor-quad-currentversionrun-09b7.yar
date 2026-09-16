rule TTP_XOR_QUAD_CurrentVersionRun_09b7 {
  strings:
    $key_09b7 = { 5a d8 [2] 7e d6 [2] 55 fa [2] 7b d8 [2] 6f c3 [2] 60 d9 [2] 7e c4 [2] 7c c5 [2] 67 c3 [2] 7b c4 [2] 67 eb }

  condition:
    any of them
}