rule TTP_XOR_QUAD_CurrentVersionRun_3ca5 {
  strings:
    $key_3ca5 = { 6f ca [2] 4b c4 [2] 60 e8 [2] 4e ca [2] 5a d1 [2] 55 cb [2] 4b d6 [2] 49 d7 [2] 52 d1 [2] 4e d6 [2] 52 f9 }

  condition:
    any of them
}