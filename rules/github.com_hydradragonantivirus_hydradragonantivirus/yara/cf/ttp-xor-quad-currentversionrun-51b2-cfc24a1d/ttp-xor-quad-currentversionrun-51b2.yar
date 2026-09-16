rule TTP_XOR_QUAD_CurrentVersionRun_51b2 {
  strings:
    $key_51b2 = { 02 dd [2] 26 d3 [2] 0d ff [2] 23 dd [2] 37 c6 [2] 38 dc [2] 26 c1 [2] 24 c0 [2] 3f c6 [2] 23 c1 [2] 3f ee }

  condition:
    any of them
}