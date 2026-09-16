rule TTP_XOR_QUAD_CurrentVersionRun_2fb2 {
  strings:
    $key_2fb2 = { 7c dd [2] 58 d3 [2] 73 ff [2] 5d dd [2] 49 c6 [2] 46 dc [2] 58 c1 [2] 5a c0 [2] 41 c6 [2] 5d c1 [2] 41 ee }

  condition:
    any of them
}