rule TTP_XOR_QUAD_CurrentVersionRun_f586 {
  strings:
    $key_f586 = { a6 e9 [2] 82 e7 [2] a9 cb [2] 87 e9 [2] 93 f2 [2] 9c e8 [2] 82 f5 [2] 80 f4 [2] 9b f2 [2] 87 f5 [2] 9b da }

  condition:
    any of them
}