rule TTP_XOR_QUAD_CurrentVersionRun_3bb2 {
  strings:
    $key_3bb2 = { 68 dd [2] 4c d3 [2] 67 ff [2] 49 dd [2] 5d c6 [2] 52 dc [2] 4c c1 [2] 4e c0 [2] 55 c6 [2] 49 c1 [2] 55 ee }

  condition:
    any of them
}