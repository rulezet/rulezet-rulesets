rule TTP_XOR_QUAD_CurrentVersionRun_5f86 {
  strings:
    $key_5f86 = { 0c e9 [2] 28 e7 [2] 03 cb [2] 2d e9 [2] 39 f2 [2] 36 e8 [2] 28 f5 [2] 2a f4 [2] 31 f2 [2] 2d f5 [2] 31 da }

  condition:
    any of them
}