rule TTP_XOR_QUAD_CurrentVersionRun_6886 {
  strings:
    $key_6886 = { 3b e9 [2] 1f e7 [2] 34 cb [2] 1a e9 [2] 0e f2 [2] 01 e8 [2] 1f f5 [2] 1d f4 [2] 06 f2 [2] 1a f5 [2] 06 da }

  condition:
    any of them
}