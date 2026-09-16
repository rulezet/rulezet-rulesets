rule TTP_XOR_QUAD_CurrentVersionRun_4a97 {
  strings:
    $key_4a97 = { 19 f8 [2] 3d f6 [2] 16 da [2] 38 f8 [2] 2c e3 [2] 23 f9 [2] 3d e4 [2] 3f e5 [2] 24 e3 [2] 38 e4 [2] 24 cb }

  condition:
    any of them
}