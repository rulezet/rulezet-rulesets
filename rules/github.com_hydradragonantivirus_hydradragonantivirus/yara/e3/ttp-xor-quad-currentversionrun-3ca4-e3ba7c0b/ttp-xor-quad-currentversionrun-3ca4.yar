rule TTP_XOR_QUAD_CurrentVersionRun_3ca4 {
  strings:
    $key_3ca4 = { 6f cb [2] 4b c5 [2] 60 e9 [2] 4e cb [2] 5a d0 [2] 55 ca [2] 4b d7 [2] 49 d6 [2] 52 d0 [2] 4e d7 [2] 52 f8 }

  condition:
    any of them
}