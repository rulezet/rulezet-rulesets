rule TTP_XOR_QUAD_CurrentVersionRun_20a5 {
  strings:
    $key_20a5 = { 73 ca [2] 57 c4 [2] 7c e8 [2] 52 ca [2] 46 d1 [2] 49 cb [2] 57 d6 [2] 55 d7 [2] 4e d1 [2] 52 d6 [2] 4e f9 }

  condition:
    any of them
}