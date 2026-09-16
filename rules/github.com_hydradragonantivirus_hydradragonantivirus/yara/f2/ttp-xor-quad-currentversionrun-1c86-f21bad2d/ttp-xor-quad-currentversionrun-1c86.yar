rule TTP_XOR_QUAD_CurrentVersionRun_1c86 {
  strings:
    $key_1c86 = { 4f e9 [2] 6b e7 [2] 40 cb [2] 6e e9 [2] 7a f2 [2] 75 e8 [2] 6b f5 [2] 69 f4 [2] 72 f2 [2] 6e f5 [2] 72 da }

  condition:
    any of them
}