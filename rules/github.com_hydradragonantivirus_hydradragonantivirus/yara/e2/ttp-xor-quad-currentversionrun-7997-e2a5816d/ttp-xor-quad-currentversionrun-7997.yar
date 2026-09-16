rule TTP_XOR_QUAD_CurrentVersionRun_7997 {
  strings:
    $key_7997 = { 2a f8 [2] 0e f6 [2] 25 da [2] 0b f8 [2] 1f e3 [2] 10 f9 [2] 0e e4 [2] 0c e5 [2] 17 e3 [2] 0b e4 [2] 17 cb }

  condition:
    any of them
}