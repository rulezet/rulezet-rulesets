rule TTP_XOR_QUAD_CurrentVersionRun_3c86 {
  strings:
    $key_3c86 = { 6f e9 [2] 4b e7 [2] 60 cb [2] 4e e9 [2] 5a f2 [2] 55 e8 [2] 4b f5 [2] 49 f4 [2] 52 f2 [2] 4e f5 [2] 52 da }

  condition:
    any of them
}