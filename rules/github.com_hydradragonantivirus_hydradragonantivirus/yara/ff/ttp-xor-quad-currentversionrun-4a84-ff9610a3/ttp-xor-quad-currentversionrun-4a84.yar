rule TTP_XOR_QUAD_CurrentVersionRun_4a84 {
  strings:
    $key_4a84 = { 19 eb [2] 3d e5 [2] 16 c9 [2] 38 eb [2] 2c f0 [2] 23 ea [2] 3d f7 [2] 3f f6 [2] 24 f0 [2] 38 f7 [2] 24 d8 }

  condition:
    any of them
}