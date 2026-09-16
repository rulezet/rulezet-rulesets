rule TTP_XOR_QUAD_CurrentVersionRun_4ab2 {
  strings:
    $key_4ab2 = { 19 dd [2] 3d d3 [2] 16 ff [2] 38 dd [2] 2c c6 [2] 23 dc [2] 3d c1 [2] 3f c0 [2] 24 c6 [2] 38 c1 [2] 24 ee }

  condition:
    any of them
}