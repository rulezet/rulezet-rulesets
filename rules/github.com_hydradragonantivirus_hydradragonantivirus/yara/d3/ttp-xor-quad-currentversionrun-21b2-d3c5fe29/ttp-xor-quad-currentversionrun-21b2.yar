rule TTP_XOR_QUAD_CurrentVersionRun_21b2 {
  strings:
    $key_21b2 = { 72 dd [2] 56 d3 [2] 7d ff [2] 53 dd [2] 47 c6 [2] 48 dc [2] 56 c1 [2] 54 c0 [2] 4f c6 [2] 53 c1 [2] 4f ee }

  condition:
    any of them
}