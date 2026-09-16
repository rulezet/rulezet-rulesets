rule TTP_XOR_QUAD_CurrentVersionRun_79b5 {
  strings:
    $key_79b5 = { 2a da [2] 0e d4 [2] 25 f8 [2] 0b da [2] 1f c1 [2] 10 db [2] 0e c6 [2] 0c c7 [2] 17 c1 [2] 0b c6 [2] 17 e9 }

  condition:
    any of them
}