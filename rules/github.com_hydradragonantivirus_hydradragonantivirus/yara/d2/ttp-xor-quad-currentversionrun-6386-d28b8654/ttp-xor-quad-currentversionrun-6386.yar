rule TTP_XOR_QUAD_CurrentVersionRun_6386 {
  strings:
    $key_6386 = { 30 e9 [2] 14 e7 [2] 3f cb [2] 11 e9 [2] 05 f2 [2] 0a e8 [2] 14 f5 [2] 16 f4 [2] 0d f2 [2] 11 f5 [2] 0d da }

  condition:
    any of them
}