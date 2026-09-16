rule TTP_XOR_QUAD_CurrentVersionRun_7d97 {
  strings:
    $key_7d97 = { 2e f8 [2] 0a f6 [2] 21 da [2] 0f f8 [2] 1b e3 [2] 14 f9 [2] 0a e4 [2] 08 e5 [2] 13 e3 [2] 0f e4 [2] 13 cb }

  condition:
    any of them
}