rule TTP_XOR_QUAD_CurrentVersionRun_79b2 {
  strings:
    $key_79b2 = { 2a dd [2] 0e d3 [2] 25 ff [2] 0b dd [2] 1f c6 [2] 10 dc [2] 0e c1 [2] 0c c0 [2] 17 c6 [2] 0b c1 [2] 17 ee }

  condition:
    any of them
}