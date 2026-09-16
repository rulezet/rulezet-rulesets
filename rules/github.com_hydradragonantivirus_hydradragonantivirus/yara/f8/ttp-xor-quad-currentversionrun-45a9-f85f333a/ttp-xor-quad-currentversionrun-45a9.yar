rule TTP_XOR_QUAD_CurrentVersionRun_45a9 {
  strings:
    $key_45a9 = { 16 c6 [2] 32 c8 [2] 19 e4 [2] 37 c6 [2] 23 dd [2] 2c c7 [2] 32 da [2] 30 db [2] 2b dd [2] 37 da [2] 2b f5 }

  condition:
    any of them
}