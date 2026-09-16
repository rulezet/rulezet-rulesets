rule TTP_XOR_QUAD_CurrentVersionRun_e7b8 {
  strings:
    $key_e7b8 = { b4 d7 [2] 90 d9 [2] bb f5 [2] 95 d7 [2] 81 cc [2] 8e d6 [2] 90 cb [2] 92 ca [2] 89 cc [2] 95 cb [2] 89 e4 }

  condition:
    any of them
}