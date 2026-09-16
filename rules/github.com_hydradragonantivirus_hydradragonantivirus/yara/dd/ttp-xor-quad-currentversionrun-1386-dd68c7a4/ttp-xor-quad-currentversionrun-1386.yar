rule TTP_XOR_QUAD_CurrentVersionRun_1386 {
  strings:
    $key_1386 = { 40 e9 [2] 64 e7 [2] 4f cb [2] 61 e9 [2] 75 f2 [2] 7a e8 [2] 64 f5 [2] 66 f4 [2] 7d f2 [2] 61 f5 [2] 7d da }

  condition:
    any of them
}