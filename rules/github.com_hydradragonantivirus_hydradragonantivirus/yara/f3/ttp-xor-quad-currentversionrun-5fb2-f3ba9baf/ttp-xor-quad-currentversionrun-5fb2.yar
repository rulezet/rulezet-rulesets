rule TTP_XOR_QUAD_CurrentVersionRun_5fb2 {
  strings:
    $key_5fb2 = { 0c dd [2] 28 d3 [2] 03 ff [2] 2d dd [2] 39 c6 [2] 36 dc [2] 28 c1 [2] 2a c0 [2] 31 c6 [2] 2d c1 [2] 31 ee }

  condition:
    any of them
}