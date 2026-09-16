rule TTP_XOR_QUAD_CurrentVersionRun_75a9 {
  strings:
    $key_75a9 = { 26 c6 [2] 02 c8 [2] 29 e4 [2] 07 c6 [2] 13 dd [2] 1c c7 [2] 02 da [2] 00 db [2] 1b dd [2] 07 da [2] 1b f5 }

  condition:
    any of them
}