rule TTP_XOR_QUAD_CurrentVersionRun_7f97 {
  strings:
    $key_7f97 = { 2c f8 [2] 08 f6 [2] 23 da [2] 0d f8 [2] 19 e3 [2] 16 f9 [2] 08 e4 [2] 0a e5 [2] 11 e3 [2] 0d e4 [2] 11 cb }

  condition:
    any of them
}