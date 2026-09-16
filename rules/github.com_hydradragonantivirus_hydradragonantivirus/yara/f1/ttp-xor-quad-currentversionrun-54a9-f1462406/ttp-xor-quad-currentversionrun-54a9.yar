rule TTP_XOR_QUAD_CurrentVersionRun_54a9 {
  strings:
    $key_54a9 = { 07 c6 [2] 23 c8 [2] 08 e4 [2] 26 c6 [2] 32 dd [2] 3d c7 [2] 23 da [2] 21 db [2] 3a dd [2] 26 da [2] 3a f5 }

  condition:
    any of them
}