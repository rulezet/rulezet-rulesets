rule TTP_XOR_QUAD_CurrentVersionRun_61b2 {
  strings:
    $key_61b2 = { 32 dd [2] 16 d3 [2] 3d ff [2] 13 dd [2] 07 c6 [2] 08 dc [2] 16 c1 [2] 14 c0 [2] 0f c6 [2] 13 c1 [2] 0f ee }

  condition:
    any of them
}