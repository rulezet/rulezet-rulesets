rule TTP_XOR_QUAD_CurrentVersionRun_f0b2 {
  strings:
    $key_f0b2 = { a3 dd [2] 87 d3 [2] ac ff [2] 82 dd [2] 96 c6 [2] 99 dc [2] 87 c1 [2] 85 c0 [2] 9e c6 [2] 82 c1 [2] 9e ee }

  condition:
    any of them
}