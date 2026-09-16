rule TTP_XOR_QUAD_CurrentVersionRun_3ba5 {
  strings:
    $key_3ba5 = { 68 ca [2] 4c c4 [2] 67 e8 [2] 49 ca [2] 5d d1 [2] 52 cb [2] 4c d6 [2] 4e d7 [2] 55 d1 [2] 49 d6 [2] 55 f9 }

  condition:
    any of them
}