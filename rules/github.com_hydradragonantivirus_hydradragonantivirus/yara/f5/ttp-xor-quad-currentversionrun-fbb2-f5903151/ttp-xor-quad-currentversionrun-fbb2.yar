rule TTP_XOR_QUAD_CurrentVersionRun_fbb2 {
  strings:
    $key_fbb2 = { a8 dd [2] 8c d3 [2] a7 ff [2] 89 dd [2] 9d c6 [2] 92 dc [2] 8c c1 [2] 8e c0 [2] 95 c6 [2] 89 c1 [2] 95 ee }

  condition:
    any of them
}