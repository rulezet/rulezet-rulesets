rule TTP_XOR_QUAD_CurrentVersionRun_1eb2 {
  strings:
    $key_1eb2 = { 4d dd [2] 69 d3 [2] 42 ff [2] 6c dd [2] 78 c6 [2] 77 dc [2] 69 c1 [2] 6b c0 [2] 70 c6 [2] 6c c1 [2] 70 ee }

  condition:
    any of them
}