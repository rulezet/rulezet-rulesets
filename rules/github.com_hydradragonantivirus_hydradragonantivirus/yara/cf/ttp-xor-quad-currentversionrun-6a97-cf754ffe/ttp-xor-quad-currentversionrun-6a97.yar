rule TTP_XOR_QUAD_CurrentVersionRun_6a97 {
  strings:
    $key_6a97 = { 39 f8 [2] 1d f6 [2] 36 da [2] 18 f8 [2] 0c e3 [2] 03 f9 [2] 1d e4 [2] 1f e5 [2] 04 e3 [2] 18 e4 [2] 04 cb }

  condition:
    any of them
}