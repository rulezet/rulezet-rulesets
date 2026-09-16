rule TTP_XOR_QUAD_CurrentVersionRun_6d97 {
  strings:
    $key_6d97 = { 3e f8 [2] 1a f6 [2] 31 da [2] 1f f8 [2] 0b e3 [2] 04 f9 [2] 1a e4 [2] 18 e5 [2] 03 e3 [2] 1f e4 [2] 03 cb }

  condition:
    any of them
}