rule TTP_XOR_QUAD_CurrentVersionRun_4ab5 {
  strings:
    $key_4ab5 = { 19 da [2] 3d d4 [2] 16 f8 [2] 38 da [2] 2c c1 [2] 23 db [2] 3d c6 [2] 3f c7 [2] 24 c1 [2] 38 c6 [2] 24 e9 }

  condition:
    any of them
}