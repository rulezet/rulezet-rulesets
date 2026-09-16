rule TTP_XOR_QUAD_CurrentVersionRun_31b2 {
  strings:
    $key_31b2 = { 62 dd [2] 46 d3 [2] 6d ff [2] 43 dd [2] 57 c6 [2] 58 dc [2] 46 c1 [2] 44 c0 [2] 5f c6 [2] 43 c1 [2] 5f ee }

  condition:
    any of them
}