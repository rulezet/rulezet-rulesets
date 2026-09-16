rule TTP_XOR_QUAD_CurrentVersionRun_fa86 {
  strings:
    $key_fa86 = { a9 e9 [2] 8d e7 [2] a6 cb [2] 88 e9 [2] 9c f2 [2] 93 e8 [2] 8d f5 [2] 8f f4 [2] 94 f2 [2] 88 f5 [2] 94 da }

  condition:
    any of them
}