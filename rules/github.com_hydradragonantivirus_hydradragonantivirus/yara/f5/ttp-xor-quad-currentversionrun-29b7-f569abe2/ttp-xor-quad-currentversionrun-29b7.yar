rule TTP_XOR_QUAD_CurrentVersionRun_29b7 {
  strings:
    $key_29b7 = { 7a d8 [2] 5e d6 [2] 75 fa [2] 5b d8 [2] 4f c3 [2] 40 d9 [2] 5e c4 [2] 5c c5 [2] 47 c3 [2] 5b c4 [2] 47 eb }

  condition:
    any of them
}