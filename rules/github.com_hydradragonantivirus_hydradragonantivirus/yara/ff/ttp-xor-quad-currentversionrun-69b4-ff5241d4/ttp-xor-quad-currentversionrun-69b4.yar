rule TTP_XOR_QUAD_CurrentVersionRun_69b4 {
  strings:
    $key_69b4 = { 3a db [2] 1e d5 [2] 35 f9 [2] 1b db [2] 0f c0 [2] 00 da [2] 1e c7 [2] 1c c6 [2] 07 c0 [2] 1b c7 [2] 07 e8 }

  condition:
    any of them
}