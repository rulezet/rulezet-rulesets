rule TTP_XOR_QUAD_CurrentVersionRun_00b2 {
  strings:
    $key_00b2 = { 53 dd [2] 77 d3 [2] 5c ff [2] 72 dd [2] 66 c6 [2] 69 dc [2] 77 c1 [2] 75 c0 [2] 6e c6 [2] 72 c1 [2] 6e ee }

  condition:
    any of them
}