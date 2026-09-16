rule TTP_XOR_QUAD_CurrentVersionRun_5eb2 {
  strings:
    $key_5eb2 = { 0d dd [2] 29 d3 [2] 02 ff [2] 2c dd [2] 38 c6 [2] 37 dc [2] 29 c1 [2] 2b c0 [2] 30 c6 [2] 2c c1 [2] 30 ee }

  condition:
    any of them
}