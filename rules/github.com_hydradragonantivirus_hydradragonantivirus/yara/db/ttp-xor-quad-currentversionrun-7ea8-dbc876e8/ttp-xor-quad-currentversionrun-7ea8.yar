rule TTP_XOR_QUAD_CurrentVersionRun_7ea8 {
  strings:
    $key_7ea8 = { 2d c7 [2] 09 c9 [2] 22 e5 [2] 0c c7 [2] 18 dc [2] 17 c6 [2] 09 db [2] 0b da [2] 10 dc [2] 0c db [2] 10 f4 }

  condition:
    any of them
}