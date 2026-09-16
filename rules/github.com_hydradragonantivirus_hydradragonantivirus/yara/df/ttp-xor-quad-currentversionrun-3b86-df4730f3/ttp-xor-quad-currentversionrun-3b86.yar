rule TTP_XOR_QUAD_CurrentVersionRun_3b86 {
  strings:
    $key_3b86 = { 68 e9 [2] 4c e7 [2] 67 cb [2] 49 e9 [2] 5d f2 [2] 52 e8 [2] 4c f5 [2] 4e f4 [2] 55 f2 [2] 49 f5 [2] 55 da }

  condition:
    any of them
}