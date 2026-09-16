rule TTP_XOR_QUAD_CurrentVersionRun_0ca4 {
  strings:
    $key_0ca4 = { 5f cb [2] 7b c5 [2] 50 e9 [2] 7e cb [2] 6a d0 [2] 65 ca [2] 7b d7 [2] 79 d6 [2] 62 d0 [2] 7e d7 [2] 62 f8 }

  condition:
    any of them
}