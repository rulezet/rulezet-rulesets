rule TTP_XOR_QUAD_CurrentVersionRun_7586 {
  strings:
    $key_7586 = { 26 e9 [2] 02 e7 [2] 29 cb [2] 07 e9 [2] 13 f2 [2] 1c e8 [2] 02 f5 [2] 00 f4 [2] 1b f2 [2] 07 f5 [2] 1b da }

  condition:
    any of them
}