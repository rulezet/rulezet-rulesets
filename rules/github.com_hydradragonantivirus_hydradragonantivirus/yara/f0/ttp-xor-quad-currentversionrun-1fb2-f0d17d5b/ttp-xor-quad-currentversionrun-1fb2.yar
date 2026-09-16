rule TTP_XOR_QUAD_CurrentVersionRun_1fb2 {
  strings:
    $key_1fb2 = { 4c dd [2] 68 d3 [2] 43 ff [2] 6d dd [2] 79 c6 [2] 76 dc [2] 68 c1 [2] 6a c0 [2] 71 c6 [2] 6d c1 [2] 71 ee }

  condition:
    any of them
}