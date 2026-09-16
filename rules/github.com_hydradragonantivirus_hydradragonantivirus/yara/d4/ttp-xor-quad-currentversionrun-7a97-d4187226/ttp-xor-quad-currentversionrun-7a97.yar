rule TTP_XOR_QUAD_CurrentVersionRun_7a97 {
  strings:
    $key_7a97 = { 29 f8 [2] 0d f6 [2] 26 da [2] 08 f8 [2] 1c e3 [2] 13 f9 [2] 0d e4 [2] 0f e5 [2] 14 e3 [2] 08 e4 [2] 14 cb }

  condition:
    any of them
}