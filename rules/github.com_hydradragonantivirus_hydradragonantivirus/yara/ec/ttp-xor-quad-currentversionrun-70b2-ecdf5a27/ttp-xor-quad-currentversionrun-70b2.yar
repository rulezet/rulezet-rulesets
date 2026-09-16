rule TTP_XOR_QUAD_CurrentVersionRun_70b2 {
  strings:
    $key_70b2 = { 23 dd [2] 07 d3 [2] 2c ff [2] 02 dd [2] 16 c6 [2] 19 dc [2] 07 c1 [2] 05 c0 [2] 1e c6 [2] 02 c1 [2] 1e ee }

  condition:
    any of them
}