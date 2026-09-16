rule TTP_XOR_QUAD_CurrentVersionRun_67a9 {
  strings:
    $key_67a9 = { 34 c6 [2] 10 c8 [2] 3b e4 [2] 15 c6 [2] 01 dd [2] 0e c7 [2] 10 da [2] 12 db [2] 09 dd [2] 15 da [2] 09 f5 }

  condition:
    any of them
}