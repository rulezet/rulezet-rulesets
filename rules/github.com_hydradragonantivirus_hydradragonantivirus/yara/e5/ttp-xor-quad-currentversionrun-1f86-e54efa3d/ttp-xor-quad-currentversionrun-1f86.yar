rule TTP_XOR_QUAD_CurrentVersionRun_1f86 {
  strings:
    $key_1f86 = { 4c e9 [2] 68 e7 [2] 43 cb [2] 6d e9 [2] 79 f2 [2] 76 e8 [2] 68 f5 [2] 6a f4 [2] 71 f2 [2] 6d f5 [2] 71 da }

  condition:
    any of them
}