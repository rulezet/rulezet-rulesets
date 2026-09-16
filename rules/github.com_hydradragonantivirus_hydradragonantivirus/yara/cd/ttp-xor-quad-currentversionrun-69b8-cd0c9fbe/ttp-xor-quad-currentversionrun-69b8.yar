rule TTP_XOR_QUAD_CurrentVersionRun_69b8 {
  strings:
    $key_69b8 = { 3a d7 [2] 1e d9 [2] 35 f5 [2] 1b d7 [2] 0f cc [2] 00 d6 [2] 1e cb [2] 1c ca [2] 07 cc [2] 1b cb [2] 07 e4 }

  condition:
    any of them
}