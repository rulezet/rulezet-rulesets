rule TTP_XOR_QUAD_CurrentVersionRun_04a9 {
  strings:
    $key_04a9 = { 57 c6 [2] 73 c8 [2] 58 e4 [2] 76 c6 [2] 62 dd [2] 6d c7 [2] 73 da [2] 71 db [2] 6a dd [2] 76 da [2] 6a f5 }

  condition:
    any of them
}