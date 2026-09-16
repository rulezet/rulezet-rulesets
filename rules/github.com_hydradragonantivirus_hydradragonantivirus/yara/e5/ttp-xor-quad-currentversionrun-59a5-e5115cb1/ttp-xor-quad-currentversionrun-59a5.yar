rule TTP_XOR_QUAD_CurrentVersionRun_59a5 {
  strings:
    $key_59a5 = { 0a ca [2] 2e c4 [2] 05 e8 [2] 2b ca [2] 3f d1 [2] 30 cb [2] 2e d6 [2] 2c d7 [2] 37 d1 [2] 2b d6 [2] 37 f9 }

  condition:
    any of them
}