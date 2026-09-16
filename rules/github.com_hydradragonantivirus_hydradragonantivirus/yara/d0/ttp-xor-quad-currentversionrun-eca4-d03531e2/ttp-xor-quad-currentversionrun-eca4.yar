rule TTP_XOR_QUAD_CurrentVersionRun_eca4 {
  strings:
    $key_eca4 = { bf cb [2] 9b c5 [2] b0 e9 [2] 9e cb [2] 8a d0 [2] 85 ca [2] 9b d7 [2] 99 d6 [2] 82 d0 [2] 9e d7 [2] 82 f8 }

  condition:
    any of them
}