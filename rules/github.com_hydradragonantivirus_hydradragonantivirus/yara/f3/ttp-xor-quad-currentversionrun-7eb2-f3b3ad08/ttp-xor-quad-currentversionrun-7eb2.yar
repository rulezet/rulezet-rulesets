rule TTP_XOR_QUAD_CurrentVersionRun_7eb2 {
  strings:
    $key_7eb2 = { 2d dd [2] 09 d3 [2] 22 ff [2] 0c dd [2] 18 c6 [2] 17 dc [2] 09 c1 [2] 0b c0 [2] 10 c6 [2] 0c c1 [2] 10 ee }

  condition:
    any of them
}