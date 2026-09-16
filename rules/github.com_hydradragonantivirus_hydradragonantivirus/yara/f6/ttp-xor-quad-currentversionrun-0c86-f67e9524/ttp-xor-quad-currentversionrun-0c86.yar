rule TTP_XOR_QUAD_CurrentVersionRun_0c86 {
  strings:
    $key_0c86 = { 5f e9 [2] 7b e7 [2] 50 cb [2] 7e e9 [2] 6a f2 [2] 65 e8 [2] 7b f5 [2] 79 f4 [2] 62 f2 [2] 7e f5 [2] 62 da }

  condition:
    any of them
}