rule TTP_XOR_QUAD_CurrentVersionRun_3386 {
  strings:
    $key_3386 = { 60 e9 [2] 44 e7 [2] 6f cb [2] 41 e9 [2] 55 f2 [2] 5a e8 [2] 44 f5 [2] 46 f4 [2] 5d f2 [2] 41 f5 [2] 5d da }

  condition:
    any of them
}