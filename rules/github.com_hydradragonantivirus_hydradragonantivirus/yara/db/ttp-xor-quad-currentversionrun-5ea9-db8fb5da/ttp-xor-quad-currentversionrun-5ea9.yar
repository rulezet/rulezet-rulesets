rule TTP_XOR_QUAD_CurrentVersionRun_5ea9 {
  strings:
    $key_5ea9 = { 0d c6 [2] 29 c8 [2] 02 e4 [2] 2c c6 [2] 38 dd [2] 37 c7 [2] 29 da [2] 2b db [2] 30 dd [2] 2c da [2] 30 f5 }

  condition:
    any of them
}