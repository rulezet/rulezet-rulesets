rule TTP_XOR_QUAD_CurrentVersionRun_3297 {
  strings:
    $key_3297 = { 61 f8 [2] 45 f6 [2] 6e da [2] 40 f8 [2] 54 e3 [2] 5b f9 [2] 45 e4 [2] 47 e5 [2] 5c e3 [2] 40 e4 [2] 5c cb }

  condition:
    any of them
}