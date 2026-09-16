rule TTP_XOR_QUAD_CurrentVersionRun_5bb4 {
  strings:
    $key_5bb4 = { 08 db [2] 2c d5 [2] 07 f9 [2] 29 db [2] 3d c0 [2] 32 da [2] 2c c7 [2] 2e c6 [2] 35 c0 [2] 29 c7 [2] 35 e8 }

  condition:
    any of them
}