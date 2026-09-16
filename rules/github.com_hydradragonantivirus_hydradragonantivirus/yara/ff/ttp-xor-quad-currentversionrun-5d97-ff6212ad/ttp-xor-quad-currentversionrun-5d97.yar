rule TTP_XOR_QUAD_CurrentVersionRun_5d97 {
  strings:
    $key_5d97 = { 0e f8 [2] 2a f6 [2] 01 da [2] 2f f8 [2] 3b e3 [2] 34 f9 [2] 2a e4 [2] 28 e5 [2] 33 e3 [2] 2f e4 [2] 33 cb }

  condition:
    any of them
}