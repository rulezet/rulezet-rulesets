rule TTP_XOR_QUAD_CurrentVersionRun_5bb2 {
  strings:
    $key_5bb2 = { 08 dd [2] 2c d3 [2] 07 ff [2] 29 dd [2] 3d c6 [2] 32 dc [2] 2c c1 [2] 2e c0 [2] 35 c6 [2] 29 c1 [2] 35 ee }

  condition:
    any of them
}