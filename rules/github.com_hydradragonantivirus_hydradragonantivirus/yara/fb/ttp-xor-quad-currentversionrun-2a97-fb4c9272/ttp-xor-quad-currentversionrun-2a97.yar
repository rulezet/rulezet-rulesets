rule TTP_XOR_QUAD_CurrentVersionRun_2a97 {
  strings:
    $key_2a97 = { 79 f8 [2] 5d f6 [2] 76 da [2] 58 f8 [2] 4c e3 [2] 43 f9 [2] 5d e4 [2] 5f e5 [2] 44 e3 [2] 58 e4 [2] 44 cb }

  condition:
    any of them
}