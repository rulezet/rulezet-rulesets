rule TTP_XOR_QUAD_CurrentVersionRun_4a86 {
  strings:
    $key_4a86 = { 19 e9 [2] 3d e7 [2] 16 cb [2] 38 e9 [2] 2c f2 [2] 23 e8 [2] 3d f5 [2] 3f f4 [2] 24 f2 [2] 38 f5 [2] 24 da }

  condition:
    any of them
}