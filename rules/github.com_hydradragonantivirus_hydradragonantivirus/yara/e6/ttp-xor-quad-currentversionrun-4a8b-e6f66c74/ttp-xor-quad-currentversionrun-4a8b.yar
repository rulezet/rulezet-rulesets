rule TTP_XOR_QUAD_CurrentVersionRun_4a8b {
  strings:
    $key_4a8b = { 19 e4 [2] 3d ea [2] 16 c6 [2] 38 e4 [2] 2c ff [2] 23 e5 [2] 3d f8 [2] 3f f9 [2] 24 ff [2] 38 f8 [2] 24 d7 }

  condition:
    any of them
}