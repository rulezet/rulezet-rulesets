rule TTP_XOR_QUAD_CurrentVersionRun_e586 {
  strings:
    $key_e586 = { b6 e9 [2] 92 e7 [2] b9 cb [2] 97 e9 [2] 83 f2 [2] 8c e8 [2] 92 f5 [2] 90 f4 [2] 8b f2 [2] 97 f5 [2] 8b da }

  condition:
    any of them
}