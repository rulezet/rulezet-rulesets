rule TTP_XOR_QUAD_CurrentVersionRun_5297 {
  strings:
    $key_5297 = { 01 f8 [2] 25 f6 [2] 0e da [2] 20 f8 [2] 34 e3 [2] 3b f9 [2] 25 e4 [2] 27 e5 [2] 3c e3 [2] 20 e4 [2] 3c cb }

  condition:
    any of them
}