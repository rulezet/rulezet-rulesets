rule TTP_XOR_QUAD_CurrentVersionRun_14a9 {
  strings:
    $key_14a9 = { 47 c6 [2] 63 c8 [2] 48 e4 [2] 66 c6 [2] 72 dd [2] 7d c7 [2] 63 da [2] 61 db [2] 7a dd [2] 66 da [2] 7a f5 }

  condition:
    any of them
}